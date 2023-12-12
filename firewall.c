#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>

#define DEVICE_NAME "firewall"
#define CLASS_NAME "fireclass"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gina, Sumin");
MODULE_DESCRIPTION("FireWall");
MODULE_VERSION("0.0");

#define MAX_IP_COUNT 100
#define MAX_IP_LENGTH 256

static char ips[MAX_IP_COUNT][MAX_IP_LENGTH];
static int ip_count = 0;

static int majorNumber;
static struct class *fireclass = NULL;
static struct device *firewall = NULL;

static int BORW;

static int mydev_open(struct inode *, struct file *);
static ssize_t mydev_read(struct file *, char *, size_t, loff_t *);
static int mydev_release(struct inode *, struct file *);

static ssize_t mydev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops = {
    .open = mydev_open,
    .read = mydev_read,
    .write = mydev_write,
    .release = mydev_release,
};

unsigned int w_hook(unsigned int hooknum, struct sk_buff *skb,
                    const struct net_device *in,
                    const struct net_device *out,
                    int (*okfn)(struct sk_buff *));
unsigned int b_hook(unsigned int hooknum, struct sk_buff *skb,
                    const struct net_device *in,
                    const struct net_device *out,
                    int (*okfn)(struct sk_buff *));

static struct nf_hook_ops w_drop __read_mostly = {
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_FIRST,
    .hooknum = NF_INET_LOCAL_IN,
    .hook = (nf_hookfn *)w_hook,
};

static struct nf_hook_ops b_drop __read_mostly = {
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_FIRST,
    .hooknum = NF_INET_LOCAL_IN,
    .hook = (nf_hookfn *)b_hook,
};

static int __init firewall_init(void)
{
    return 0;
}

static void __exit firewall_exit(void)
{
    return 0;
}

static int mydev_open(struct inode *inodep, struct file *filep)
{
    return 0;
}

static ssize_t mydev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
    return 0;
}

static ssize_t mydev_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
    return 0;
}

static int mydev_release(struct inode *inodep, struct file *filep)
{
    return 0;
}

unsigned int b_hook(unsigned int hooknum, struct sk_buff *skb,
                    const struct net_device *in, const struct net_device *out,
                    int (*okfn)(struct sk_buff *))
{
    return 0;
}

unsigned int w_hook(unsigned int hooknum, struct sk_buff *skb,
                    const struct net_device *in, const struct net_device *out,
                    int (*okfn)(struct sk_buff *))
{
    return 0;
}

module_init(firewall_init);
module_exit(firewall_exit);
