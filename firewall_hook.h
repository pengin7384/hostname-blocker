#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/inet.h>

#ifndef FIREWALL_RULE
#define RULE_ACCEPT 0
#define RULE_DROP 1
#endif

MODULE_LICENSE("GPL");

static struct nf_hook_ops *n_h_o = NULL;
static __s8 **rules = NULL;
static __u32 rule_num = 0;

__s32 hostcmp(const __s8 *rule_str, const __u8 *host_str)
{
	__u32 i = 0;

	do {
		if (rule_str[i] != (__s8)host_str[i]) {
			return 1;
		}
		i++;
	} while(rule_str[i] && (__s8)host_str[i] != '\r');

	if (!rule_str[i] && host_str[i] == '\r') {
		printk(KERN_INFO "Blocked %s\n", rule_str);
		return 0;
	}
	return 1;
}

__s32 isDropRule(__u8 *http_start, __u8 *http_tail)
{
	/* Get, Post check */
	__s32 method_check = 0;
	__s32 detect = 0;
       	__u32 len = (http_tail - http_start) / 4;	
	__u32 i, r_i;
		
	for (i = 0; i < len; i++) {
		if (len - i >= 2 && http_start[i] == '\r'
				&& http_start[i+1] == '\n') {
			break;
		} else if (len - i >= 3 
				&& http_start[i] == 'G'
				&& http_start[i+1] == 'E'
				&& http_start[i+2] == 'T') {
			method_check = 1;
		} else if (len - i >= 4 
				&& http_start[i] == 'P'
				&& http_start[i+1] == 'O'
				&& http_start[i+2] == 'S'
				&& http_start[i+3] == 'T') {
			method_check = 2;
		}
	}

	if (method_check) {
		i += 2; // \r\n
		i += 6; // Host: 
		detect = 0;
		for (r_i = 0; r_i < rule_num; r_i++) {
			if (hostcmp(rules[r_i], &http_start[i]) == 0) {
				detect = 1;
				break;
			}
		}
		
		if (detect) {
			return 1;
		}

	}
	

	return 0;
}

__s32 isHttpPacket(struct sk_buff *skb, __u8 **p_http_start, 
		__u8 **p_http_tail)
{
	struct iphdr *ip_hd;
	struct tcphdr *tcp_hd;

	ip_hd = ip_hdr(skb);
	if (ip_hd->protocol == IPPROTO_TCP) {
		tcp_hd = tcp_hdr(skb);
		if (cpu_to_be16(tcp_hd->dest) == 0x0050) {
			*p_http_start = (__u8*)((__u8*)tcp_hd + 
					(4 * tcp_hd->doff));
			*p_http_tail = skb_tail_pointer(skb);
			return 1;
		}
	}
	return 0;
}


__s32 isDropPacket(struct sk_buff *skb)
{
	__u8 *http_start = NULL;
	__u8 *http_tail = NULL;
	
	if (isHttpPacket(skb, &http_start, &http_tail)) {
		if (isDropRule(http_start, http_tail)) {
			return 1;
		}	
	}

	return 0;
}




static __u32 hookFunc(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	if (!skb) {
		return NF_ACCEPT;
	}

	if (isDropPacket(skb)) {
		return NF_DROP;
	}

	return NF_ACCEPT;
}


void hookStart(__u32 input_rule_num, __s8 **input_rules)
{

	rule_num = input_rule_num;
	rules = input_rules;	


	n_h_o = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops),
			GFP_KERNEL);
	n_h_o->hook 	= (nf_hookfn*)hookFunc;
	n_h_o->hooknum 	= NF_INET_LOCAL_OUT;
	n_h_o->priority = NF_IP_PRI_FIRST;
	n_h_o->pf	= PF_INET;

	nf_register_net_hook(&init_net, n_h_o);
	
	printk(KERN_INFO "Hook started\n");
	
}

void hookFinish(void)
{
	
	nf_unregister_net_hook(&init_net, n_h_o);
	kfree(n_h_o);
	printk(KERN_INFO "Hook Finished\n");
	
}
