#include <linux/slab.h>
#include "firewall_hook.h"

MODULE_LICENSE("GPL");

void initFilter(__s8 *rule_string)
{
	__u32 i, r_i = 0;
	__s8 *prev = rule_string;
	__s8 **rules = NULL;
	__u32 rule_num = 0;

	for (i = 0; rule_string[i]; i++) {
		if (rule_string[i] == '|') {
			rule_num++;
		}
	}

	rules = (__s8**)kmalloc_array(rule_num, sizeof(__s8**),
			GFP_KERNEL);

	for (i = 0; rule_string[i]; i++) {
		if (rule_string[i] == '|') {
			rules[r_i++] = prev;
			prev = &rule_string[i+1];
			rule_string[i] = 0;
		}
	}

	printk(KERN_INFO "Rule list (%u)\n", rule_num);
	for (i = 0; i < rule_num; i++) {
		printk(KERN_INFO "(%s)\n", rules[i]);
	}


	hookStart(rule_num, rules);
}

void addFilter(__s8 *rule_string) 
{
	initFilter(rule_string);
}



void delFilter(void)
{
	hookFinish();
	kfree(rules);
}

