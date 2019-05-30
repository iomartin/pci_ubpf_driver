#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pci-p2pdma.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/pfn_t.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>

#include <ebpf-offload.h>

#define PCI_VENDOR_EIDETICOM 0x1de5
#define PCI_QEMU_DEVICE_ID   0x3000

#define KiB                  (1*1024)
#define MiB                  (KiB*1024)

#define EBPF_SIZE            (16*MiB)
#define P2PDMA_SIZE          (8*MiB)
#define P2PDMA_OFFSET        0x800000

#define BAR 4

MODULE_LICENSE("GPL");

static int max_devices = 16;
module_param(max_devices, int, 0444);
MODULE_PARM_DESC(max_devices, "Maximum number of char devices");

static struct class *pci_ubpf_class;
static DEFINE_IDA(p2pmem_ida);
static dev_t pci_ubpf_devt;

static struct pci_device_id pci_ubpf_id_table[] = {
    { PCI_DEVICE(PCI_VENDOR_EIDETICOM, 0x3000), },
    { 0, }
};
MODULE_DEVICE_TABLE(pci, pci_ubpf_id_table);

struct pci_ubpf_dev {
    struct device dev;
    struct pci_dev *pdev;
    int id;
    struct cdev cdev;
    struct {
        volatile uint8_t  __iomem *opcode;
        volatile uint8_t  __iomem *ctrl;
        volatile uint32_t __iomem *length;
        volatile uint32_t __iomem *offset;
        volatile uint64_t __iomem *addr;

        volatile uint64_t __iomem *ret;
    } registers;
    void __iomem *mmio;
};

static inline bool watch_and_sleep(volatile uint8_t *ptr, uint8_t mask, unsigned long ms)
{
    unsigned iters = 100;
    unsigned long time_per_iter = ms/iters;

    for (unsigned i = 0; i < iters; i++) {
        if ((readb(ptr) & mask))
            return 1;
        msleep(time_per_iter);
    }
    return 0;
}

static struct pci_ubpf_dev *to_pci_ubpf(struct device *dev)
{
    return container_of(dev, struct pci_ubpf_dev, dev);
}

static int pci_ubpf_open(struct inode *inode, struct file *filp)
{
    struct pci_ubpf_dev *p;

    p = container_of(inode->i_cdev, struct pci_ubpf_dev, cdev);
    filp->private_data = p;

    return 0;
}

ssize_t pci_ubpf_read(struct file *filp, char __user *buff, size_t count, loff_t *f_pos)
{
    struct pci_ubpf_dev *p = filp->private_data;
    ssize_t retval = 0;
    ssize_t bar_len = pci_resource_len(p->pdev, BAR);

    if (*f_pos > bar_len)
        goto out;
    if (*f_pos + count > bar_len)
        count = bar_len - *f_pos;

    if (copy_to_user(buff, p->mmio + *f_pos, count)) {
        retval = -EFAULT;
        goto out;
    }
    *f_pos += count;
    retval = count;
out:
    pr_info(KBUILD_MODNAME ": Read %lu bytes. Return = %lu\n", count, retval);
    return retval;
}

ssize_t pci_ubpf_write(struct file *filp, const char __user *buff, size_t count, loff_t *f_pos)
{
    struct pci_ubpf_dev *p = filp->private_data;
    ssize_t retval = 0;
    ssize_t bar_len = pci_resource_len(p->pdev, BAR);

    if (*f_pos > bar_len)
        goto out;
    if (*f_pos + count > bar_len)
        count = bar_len - *f_pos;

    if (copy_to_user(p->mmio + *f_pos, buff, count)) {
        retval = -EFAULT;
        goto out;
    }
    *f_pos += count;
    retval = count;
out:
    pr_info(KBUILD_MODNAME ": Wrote %lu bytes. Return = %lu\n", count, retval);
    return retval;
}

int pci_ubpf_mmap (struct file *filp, struct vm_area_struct *vma)
{
    struct pci_ubpf_dev *p = filp->private_data;
    ssize_t bar_len = pci_resource_len(p->pdev, BAR);
    unsigned long start = pci_resource_start(p->pdev, BAR);

    return vm_iomap_memory(vma, start, bar_len);
}

static int run_program(struct pci_ubpf_dev *p, uint64_t offset)
{
    int finished;
    volatile uint8_t *ready = p->mmio + 0x200004;

    writeb(EBPF_OFFLOAD_OPCODE_RUN_PROG, p->registers.opcode);
    writel(offset, p->registers.offset);
    writeb(EBPF_CTRL_START, p->registers.ctrl);

    finished = watch_and_sleep(ready, 0x1, 100);

    return finished ? readq(p->registers.ret) : -ETIME;
}

/* Adapted from https://stackoverflow.com/a/5540080 */
static int do_dma(struct pci_ubpf_dev *p, uint8_t opcode, unsigned long addr, unsigned long nbytes)
{
    int ret = 0;
    int n_user_pages, n_sg;
    unsigned i, offset = 0;
    struct device *dev = &p->pdev->dev;
    unsigned long first_page = (addr & PAGE_MASK) >> PAGE_SHIFT;
    unsigned long last_page = ((addr + nbytes - 1) & PAGE_MASK) >> PAGE_SHIFT;
    unsigned first_page_offset = offset_in_page(addr);
    unsigned npages = last_page - first_page + 1;
    struct page **pages;
    struct scatterlist *sgl, *sg;

    pages = kmalloc_array(npages, sizeof(*pages), GFP_KERNEL);
    if (unlikely(!pages)) {
        ret = -ENOMEM;
        goto out;
    }

    n_user_pages = get_user_pages_fast(addr, npages, 0, pages);
    if (n_user_pages < 0) {
        dev_err(dev, "Failed at get_user_pages(): %d\n", n_user_pages);
        ret = n_user_pages;
        goto out_free_pages;
    }

    sgl = kmalloc_array(n_user_pages, sizeof(struct scatterlist), GFP_KERNEL);
    if (unlikely(!sgl)) {
        ret = -ENOMEM;
        goto out_free_pages;
    }

    sg_init_table(sgl, n_user_pages);
    /* first page */
    sg_set_page(&sgl[0], pages[0], nbytes < (PAGE_SIZE - first_page_offset) ? nbytes : (PAGE_SIZE -first_page_offset) /* len */, offset_in_page(addr));
    /* middle pages */
    for(int i = 1; i < n_user_pages - 1; i++)
        sg_set_page(&sgl[i], pages[i], PAGE_SIZE, 0);
    /* last page */
    if (n_user_pages > 1)
        sg_set_page(&sgl[n_user_pages-1], pages[n_user_pages-1], nbytes - (PAGE_SIZE - first_page_offset) - ((n_user_pages-2)*PAGE_SIZE), 0);

    n_sg = dma_map_sg(dev, sgl, n_user_pages, DMA_TO_DEVICE);
    if (n_sg == 0) {
        ret = -EIO;
        goto out_free_sgl;
    }
    for_each_sg(sgl, sg, n_sg, i) {
        writeb(opcode, p->registers.opcode);
        writel(sg_dma_len(sg), p->registers.length);
        writeq(sg_dma_address(sg), p->registers.addr);
        writel(offset, p->registers.offset);
        offset += sg_dma_len(sg);
        writeb(EBPF_CTRL_START, p->registers.ctrl);

        /* Check if DMA is finished. This bit will be set by the device */
        if (!watch_and_sleep(p->registers.ctrl, EBPF_CTRL_DMA_DONE, 100)) {
            dev_err(dev, "DMA timed out\n");
            ret = -ETIME;
            break;
        }
    }

    for (int i = 0; i < n_user_pages; i++) {
        put_page(pages[i]);
    }

    dma_unmap_sg(dev, sgl, n_user_pages, DMA_TO_DEVICE);
out_free_sgl:
    kfree(sgl);
out_free_pages:
    kfree(pages);
out:
    return ret;
}

static int copy_p2p(struct pci_ubpf_dev *p, uint8_t opcode, unsigned long addr, unsigned long nbytes)
{
    int ret = 0;
    struct device *dev = &p->pdev->dev;

    writeb(opcode, p->registers.opcode);
    writel(nbytes, p->registers.length);
    writel(0, p->registers.offset);
    writeq(addr, p->registers.addr);
    writeb(EBPF_CTRL_START, p->registers.ctrl);

    if (!watch_and_sleep(p->registers.ctrl, EBPF_CTRL_DMA_DONE, 100)) {
        dev_err(dev, "Copying data from p2p to internal area timed out\n");
        ret = -ETIME;
    }

    return ret;
}

static int get_registers(struct pci_ubpf_dev *p, uint64_t addr)
{
    int ret = copy_to_user((void *) addr, p->mmio + 0x200008, EBPF_NREGS * 64);
    return ret == EBPF_NREGS * 64 ? 0 : -EIO;
}

long pci_ubpf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret = 0;
    struct pci_ubpf_dev *p = filp->private_data;
    struct ebpf_command *ebpf_cmd = (struct ebpf_command *) arg;

    switch (ebpf_cmd->opcode) {
        case EBPF_OFFLOAD_OPCODE_DMA_TEXT:
        case EBPF_OFFLOAD_OPCODE_DMA_DATA:
            ret = do_dma(p, ebpf_cmd->opcode, ebpf_cmd->addr, ebpf_cmd->length);
            break;
        case EBPF_OFFLOAD_OPCODE_MOVE_P2P_TEXT:
        case EBPF_OFFLOAD_OPCODE_MOVE_P2P_DATA:
            copy_p2p(p, ebpf_cmd->opcode, ebpf_cmd->addr, ebpf_cmd->length);
            break;
        case EBPF_OFFLOAD_OPCODE_RUN_PROG:
            ret = run_program(p, ebpf_cmd->addr);
            break;
        case EBPF_OFFLOAD_OPCODE_GET_REGS:
            ret = get_registers(p, ebpf_cmd->addr);
            break;
        case EBPF_OFFLOAD_OPCODE_DUMP_MEM:
            writeb(EBPF_OFFLOAD_OPCODE_DUMP_MEM, p->registers.opcode);
            writeb(0x1,  p->registers.ctrl);
        default:
            ret = -EINVAL;
            printk("Opcode %d not supported/implemented\n", ebpf_cmd->opcode);
            break;
    }
    return ret;
}

loff_t pci_ubpf_llseek(struct file *filp, loff_t off, int whence)
{
    loff_t newpos;
    switch(whence) {
        case 0: /* SEEK_SET */
            newpos = off;
            break;
        case 1: /* SEEK_CUR */
            newpos = filp->f_pos + off;
            break;
        case 2: /* SEEK_END */
            newpos = EBPF_SIZE;
            break;
        default: /* can't happen */
            return -EINVAL;
    }
    if (newpos < 0) return -EINVAL;
    filp->f_pos = newpos;
    return newpos;
}

static const struct file_operations pci_ubpf_fops = {
    .owner = THIS_MODULE,
    .open =  pci_ubpf_open,
    .read =  pci_ubpf_read,
    .write = pci_ubpf_write,
    .mmap =  pci_ubpf_mmap,
    .llseek = pci_ubpf_llseek,
    .unlocked_ioctl = pci_ubpf_ioctl,
};

static void pci_ubpf_release(struct device *dev)
{
    struct pci_ubpf_dev *p = to_pci_ubpf(dev);

    kfree(p);
}

static struct pci_ubpf_dev *pci_ubpf_create(struct pci_dev *pdev)
{
    struct pci_ubpf_dev *p;
    int err;

    p = kzalloc(sizeof(*p), GFP_KERNEL);
    if (!p)
        return ERR_PTR(-ENOMEM);

    p->pdev = pdev;

    device_initialize(&p->dev);
    p->dev.class = pci_ubpf_class;
    p->dev.parent = &pdev->dev;
    p->dev.release = pci_ubpf_release;

    p->id = ida_simple_get(&p2pmem_ida, 0, 0, GFP_KERNEL);
    if (p->id < 0) {
        err = p->id;
        goto out_free;
    }

    dev_set_name(&p->dev, "pci_ubpf%d", p->id);
    p->dev.devt = MKDEV(MAJOR(pci_ubpf_devt), p->id);

    if (pci_request_region(p->pdev, BAR, "pci_ubpf_bar4")) {
        err = -EBUSY;
        goto out_free;
    }
    p->mmio = pci_iomap(pdev, BAR, pci_resource_len(pdev, BAR));
    p->registers.opcode = p->mmio + 0x0;
    p->registers.ctrl   = p->mmio + 0x1;
    p->registers.length = p->mmio + 0x4;
    p->registers.offset = p->mmio + 0x8;
    p->registers.addr   = p->mmio + 0xc;
    p->registers.ret    = p->mmio + 1*MiB;

    cdev_init(&p->cdev, &pci_ubpf_fops);
    p->cdev.owner = THIS_MODULE;

    err = cdev_device_add(&p->cdev, &p->dev);
    if (err)
        goto out_ida;

    dev_info(&p->dev, "registered");

    return p;

out_ida:
    ida_simple_remove(&p2pmem_ida, p->id);
out_free:
    kfree(p);
    return ERR_PTR(err);
}

void pci_ubpf_destroy(struct pci_ubpf_dev *p)
{
    dev_info(&p->dev, "unregistered");
    pci_release_region(p->pdev, BAR);
    cdev_device_del(&p->cdev, &p->dev);
    ida_simple_remove(&p2pmem_ida, p->id);
    put_device(&p->dev);
}

static int pci_ubpf_probe(struct pci_dev *pdev,
        const struct pci_device_id *id)
{
    struct pci_ubpf_dev *p;
    int err = 0;

    if (pci_enable_device_mem(pdev) < 0) {
        dev_err(&pdev->dev, "unable to enable device!\n");
        goto out;
    }

    if (dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
        dev_err(&pdev->dev, "pci_ubpf: No suitable DMA available\n");
        goto out_disable_device;
    }

    if (pci_p2pdma_add_resource(pdev, BAR, P2PDMA_SIZE, P2PDMA_OFFSET)) {
        dev_err(&pdev->dev, "unable to add p2p resource");
        goto out_disable_device;
    }

    pci_set_master(pdev);
    pci_p2pmem_publish(pdev, true);

    p = pci_ubpf_create(pdev);

    if (IS_ERR(p))
        goto out_disable_device;

    pci_set_drvdata(pdev, p);

    return 0;

out_disable_device:
    pci_disable_device(pdev);
out:
    return err;
}

static void pci_ubpf_remove(struct pci_dev *pdev)
{
    struct pci_ubpf_dev *p = pci_get_drvdata(pdev);

    pci_ubpf_destroy(p);
}

static struct pci_driver pci_ubpf_driver = {
    .name = "pci_ubpf",
    .id_table = pci_ubpf_id_table,
    .probe = pci_ubpf_probe,
    .remove = pci_ubpf_remove,
};

static void ugly_hack_deinit(void)
{
    struct class_dev_iter iter;
    struct device *dev;
    struct pci_ubpf_dev *p;

    class_dev_iter_init(&iter, pci_ubpf_class, NULL, NULL);
    while ((dev = class_dev_iter_next(&iter))) {
        p = to_pci_ubpf(dev);
        pci_ubpf_destroy(p);
    }
    class_dev_iter_exit(&iter);
}

static int __init pci_ubpf_init(void)
{
    int rc;

    pci_ubpf_class = class_create(THIS_MODULE, "pci_ubpf_device");
    if (IS_ERR(pci_ubpf_class))
        return PTR_ERR(pci_ubpf_class);

    rc = alloc_chrdev_region(&pci_ubpf_devt, 0, max_devices, "pci_ubpf");
    if (rc)
        goto err_class;

    rc = pci_register_driver(&pci_ubpf_driver);
    if (rc)
        goto err_chdev;

    pr_info(KBUILD_MODNAME ": module loaded\n");

    return 0;
err_chdev:
    unregister_chrdev_region(pci_ubpf_devt, max_devices);
err_class:
    class_destroy(pci_ubpf_class);
    return rc;
}

static void __exit pci_ubpf_cleanup(void)
{
    pci_unregister_driver(&pci_ubpf_driver);
    ugly_hack_deinit();
    unregister_chrdev_region(pci_ubpf_devt, max_devices);
    class_destroy(pci_ubpf_class);
    pr_info(KBUILD_MODNAME ": module unloaded\n");
}


module_init(pci_ubpf_init);
module_exit(pci_ubpf_cleanup);
