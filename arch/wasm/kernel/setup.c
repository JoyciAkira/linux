#include <asm/bug.h>
#include <asm/globals.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/sysmem.h>
#include <asm/process_events.h>
#include <linux/libfdt.h>
#include <linux/memblock.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/screen_info.h>
#include <linux/start_kernel.h>

void __wasm_call_ctors(void);
int __init setup_early_printk(char *buf);
void __init smp_init_cpus(unsigned int ncpus);
void __init init_sections(unsigned long node);

char *__initramfs_start;
unsigned long __initramfs_size;

static int do_start_kernel(void *unused)
{
	set_current_cpu(0);
	set_current_task(&init_task);
	start_kernel();
	/* start_kernel is __noreturn (ends in the cpu0 idle loop); the int
	 * signature exists so the registry's call_indirect type matches
	 * exactly — wasm indirect calls trap on signature mismatch. */
	return 0;
}

__attribute__((export_name("boot"))) void __init _start(void)
{
	static char devicetree[2048];
	static char initramfs[512];
	int node;

	/* K5: capture the pristine root stack top before anything mutates the
	 * stack global; the boot continuation re-adopts it in kwa_task_entry. */
	kwa_boot_stack_capture();

	set_current_cpu(0);
	set_current_task(&init_task);

	memblock_reserve(0, (phys_addr_t)&__heap_base);

	__initramfs_start = initramfs;
	__initramfs_size = wasm_boot_get_initramfs(initramfs, ARRAY_SIZE(initramfs));

	wasm_boot_get_devicetree(devicetree, ARRAY_SIZE(devicetree));
	BUG_ON(!early_init_dt_scan(devicetree));
	early_init_fdt_scan_reserved_mem();

	node = fdt_path_offset(devicetree, "/chosen/sections");
	if (node < 0)
		__builtin_trap();

	setup_early_printk(NULL);
	__wasm_call_ctors();
	init_sections(node);

	// ensure that any future work done on this thread won't interfere with the kernel
	set_current_cpu(-2); // -1 is reserved for unscheduled tasks
	set_current_task(NULL);

	/* K5: the boot continuation is started by the host from the kernel
	 * registry (wire token 0) once this export returns — start_kernel then
	 * runs as the preserved kernel root stack. Bound to &init_task so the
	 * idle's opaque self/next token resolves to this same slot. */
	kwa_boot_register(&init_task, do_start_kernel);
	wasm_kernel_spawn_worker(do_start_kernel, NULL, "boot",
				 sizeof "boot" - 1, false, 0, 0);
}

void __init setup_arch(char **cmdline_p)
{
	static char command_line[COMMAND_LINE_SIZE];
	int ret, ncpus;
	strscpy(command_line, boot_command_line, COMMAND_LINE_SIZE);
	*cmdline_p = command_line;

	parse_early_param();

	pr_info("Heap:\t%p -> %p = %td\n", &__heap_base, &__heap_end,
		&__heap_end - &__heap_base);
	pr_info("Stack:\t%p -> %p = %td\n", &__stack_low, &__stack_high,
		&__stack_high - &__stack_low);

	BUG_ON(THREAD_SIZE <
	       (&__stack_high - &__stack_low) + sizeof(struct task_struct));

	unflatten_device_tree();

	ret = of_property_read_u32(of_chosen, "ncpus", &ncpus);
	if (ret) {
		pr_warn("failed to read '/chosen/ncpus', defaulting to 1: %d\n", ret);
		ncpus = 1;
	}
	smp_init_cpus(ncpus);

	memblock_dump_all();

	zones_init();

	/* SR0.10: Initialize process telemetry run identity */
	zn_init_run_identity();
}

void machine_restart(char *cmd)
{
	pr_info("restart %s\n", cmd);
	BUG();
}

void machine_halt(void)
{
	pr_info("halt\n");
	BUG();
}
void machine_power_off(void)
{
	pr_info("poweroff\n");
	BUG();
}
