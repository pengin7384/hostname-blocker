#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include "firewall_filter.h"

#define BUF 1024

MODULE_LICENSE("GPL");

static __s8 rule_string[BUF];

module_param_string(input, rule_string, BUF, S_IRUGO);

static __s32 __init firewall_init(void)
{
	printk(KERN_INFO "Firewall module started\n");
	addFilter(rule_string);
	return 0;
}

static void __exit firewall_exit(void)
{
	delFilter();
	printk(KERN_INFO "Firewall module exited\n");
}

module_init(firewall_init);
module_exit(firewall_exit);

