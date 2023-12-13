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
	printk(KERN_INFO "System: Initializing the firewall\n");

	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	if (majorNumber < 0) {
		printk(KERN_ALERT "Failed\n");
		return majorNumber;
	}

	fireclass = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(fireclass)) {  
		printk(KERN_ALERT "Failed\n");         
		unregister_chrdev(majorNumber, DEVICE_NAME);
		return PTR_ERR(fireclass);
	}

	firewall = device_create(fireclass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	if (IS_ERR(firewall)) {              
		printk(KERN_ALERT "Failed\n");
		class_destroy(fireclass);           
		unregister_chrdev(majorNumber, DEVICE_NAME);
		return PTR_ERR(firewall);
	}

	return  0;
}

static void __exit firewall_exit(void)
{
    device_destroy(fireclass, MKDEV(majorNumber, 0));   
	class_unregister(fireclass);                         
	class_destroy(fireclass);                    
	unregister_chrdev(majorNumber, DEVICE_NAME); 
    nf_unregister_net_hook(&init_net,&w_drop); 
    nf_unregister_net_hook(&init_net,&b_drop);
}

static int mydev_open(struct inode *inodep, struct file *filep)
{
    i = 0;
   	printk(KERN_INFO "firewall: Device has been opened \n");
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
