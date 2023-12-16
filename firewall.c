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
static unsigned int ip_count = 0;

static unsigned int k = 0;

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

    printk(KERN_INFO "Init Success\n");

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
    ip_count = 0;
   	printk(KERN_INFO "opened \n");
   	return 0;
}

static ssize_t mydev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
    copy_from_user(ips[ip_count], buffer, 256);
   	printk(KERN_INFO "ips: %s \n", ips[ip_count]);
   	
    ip_count++;

   	if(strncmp(ips[0],"whitelist", 9) == 0) {
   		BORW = 0;
   		int rete1 = nf_register_net_hook(&init_net, &w_drop);
       	if(rete1){
         	printk(KERN_ALERT "FAILED\n");
       	}
   		printk(KERN_INFO "white list\n");
   	}
   	else if(strncmp(ips[0],"blacklist", 9) == 0) {
   		BORW = 1;
   		int rete = nf_register_net_hook(&init_net, &b_drop);
        if(rete){
        	printk(KERN_ALERT "FAILED\n");
        }
   		printk(KERN_INFO "block list\n");
   	}
   	else {
   		return 0;
   	}

    return len;
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
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    unsigned int dest_port, source_port;
    struct sk_buff *sock_buff;
    struct iphdr *ip_header;
    sock_buff = skb;
    ip_header = (struct iphdr *)skb_network_header(sock_buff);
    static char  myipb[256];
    ip_header = (struct iphdr *)skb_network_header(sock_buff);
    
    if(!sock_buff) { 
        return NF_DROP;
    }

    snprintf(myipb, 16, "%pI4", &ip_header->saddr);
    if (ip_header->protocol == 17) {
        udp_header = (struct udphdr *)(skb_transport_header(skb));
        source_port = (unsigned int)ntohs(udp_header->source);
        dest_port = (unsigned int)ntohs(udp_header->dest);
    } 
    else if(ip_header->protocol == 6) {
        tcp_header = (struct tcphdr *)(skb_transport_header(skb));
        source_port = (unsigned int)ntohs(tcp_header->source);
        dest_port = (unsigned int)ntohs(tcp_header->dest);
    }
    else {
        source_port = 0;
        dest_port = 0;
    }

    for (k = 1; k < ip_count ; ++k)
        {
            if(strncmp(myipb,ips[k],strlen(myipb)) == 0){
                printk(KERN_INFO "src_ip: %pI4 ** src port: %d\n", &ip_header->saddr,source_port);
                printk(KERN_INFO "dst_ip: %pI4 ** dst port :%d\n", &ip_header->daddr,dest_port);
                return NF_DROP;
            }

            else if(strncmp(myipb,ips[k],strlen(myipb)) != 0) {
                printk(KERN_INFO "src_ip: %pI4 ** src port: %d\n", &ip_header->saddr,source_port);
                printk(KERN_INFO "dst_ip: %pI4 ** dst port :%d\n", &ip_header->daddr,dest_port);
                return NF_ACCEPT;
            }
        }
    return 0;
}

unsigned int w_hook(unsigned int hooknum, struct sk_buff *skb,
                    const struct net_device *in, const struct net_device *out,
                    int (*okfn)(struct sk_buff *))
{
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    unsigned int dest_port, source_port;
    struct sk_buff *sock_buff;
    struct iphdr *ip_header;
    sock_buff = skb;
    ip_header = (struct iphdr *)skb_network_header(sock_buff);
    static char myip[256];
    ip_header = (struct iphdr *)skb_network_header(sock_buff);

    if(!sock_buff) { 
        return NF_DROP;
    }

    snprintf(myip, 16, "%pI4", &ip_header->saddr);

    if (ip_header->protocol == 17) {     
        udp_header = (struct udphdr *)(skb_transport_header(skb));
        source_port = (unsigned int)ntohs(udp_header->source);
        dest_port = (unsigned int)ntohs(udp_header->dest);
    } 
    else if(ip_header->protocol == 6) {  
        tcp_header = (struct tcphdr *)(skb_transport_header(skb));
        source_port = (unsigned int)ntohs(tcp_header->source);
        dest_port = (unsigned int)ntohs(tcp_header->dest);
    }
    else {
        source_port = 0;
        dest_port = 0;
    }

    for ( k = 0; k < ip_count ; ++k)
    {
        if(strncmp(myip,ips[k],strlen(myip)) != 0) {
            printk(KERN_INFO "src ip: %pI4 ** src port: %d\n", &ip_header->saddr,source_port);
            printk(KERN_INFO "dst ip: %pI4\n", &ip_header->daddr);
            return NF_DROP;
        }

        else if(strncmp(myip,ips[k],strlen(myip)) == 0) {
            printk(KERN_INFO "src ip: %pI4 ** src port: %d\n", &ip_header->saddr,source_port);
            printk(KERN_INFO "dst ip: %pI4\n", &ip_header->daddr);
            return NF_ACCEPT;
        }
    }
    return 0;
}

module_init(firewall_init);
module_exit(firewall_exit);