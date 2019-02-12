#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pci-p2pdma.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/pfn_t.h>
#include <linux/uaccess.h>

#define PCI_VENDOR_EIDETICOM 0x1de5
#define PCI_QEMU_DEVICE_ID   0x3000

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
    void __iomem *mmio;
};

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

static const struct file_operations pci_ubpf_fops = {
    .owner = THIS_MODULE,
    .open =  pci_ubpf_open,
    .read =  pci_ubpf_read,
    .write = pci_ubpf_write,
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

static void create_devices(void)
{
    struct pci_dev *pdev = NULL;
    struct pci_ubpf_dev *p;

    while ((pdev = pci_get_device(PCI_VENDOR_EIDETICOM, PCI_QEMU_DEVICE_ID, pdev))) {
        if (pdev)
            pr_info("Found device: %hu %hu\n", pdev->vendor, pdev->device);
        else
            pr_info("Did not find device\n");
        p = pci_ubpf_create(pdev);
        if (!p)
            continue;
    }
}

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

    //create_devices();

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
