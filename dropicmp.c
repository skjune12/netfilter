#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static unsigned int hook_ipv4 (
                void *priv,
                struct sk_buff *skb,
                const struct nf_hook_state *state)
{
        struct iphdr *iph;

        iph = (struct iphdr *)skb_network_header(skb);
        skb->transport_header = skb->network_header + (iph->ihl * 4);

        switch (iph->protocol) {
                case IPPROTO_TCP:
                        return NF_ACCEPT;
                        break;

                case IPPROTO_UDP:
                        return NF_ACCEPT;
                        break;

                case IPPROTO_ICMP:
                        printk(KERN_INFO "ICMP Packet!");
                        return NF_DROP;
                        break;

                default:
                        return NF_ACCEPT;
        }
}

static struct nf_hook_ops nfho4 = {
        .hook           = hook_ipv4,
        .hooknum        = NF_INET_PRE_ROUTING,
        .pf             = NFPROTO_IPV4,
        .priority       = NF_IP_PRI_FIRST
};

static int __init dropicmp_init(void)
{
        printk(KERN_INFO "Register netfilter module.");
        nf_register_hook(&nfho4);

        return 0;
}

static void __exit dropicmp_exit(void)
{
        printk(KERN_INFO "bye");
        nf_unregister_hook(&nfho4);
}

module_init(dropicmp_init);
module_exit(dropicmp_exit);

MODULE_AUTHOR("Kohei SUZUKI");
MODULE_DESCRIPTION("Filter");
MODULE_LICENSE("GPL");
