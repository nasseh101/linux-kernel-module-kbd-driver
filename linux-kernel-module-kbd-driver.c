#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/keyboard.h>
#include <linux/spinlock.h>
#include <linux/kdb.h>
#include <linux/ctype.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
#include <linux/init.h>


#define MY_WORK_QUEUE_NAME "WQsched.c"
#define KBD_STATUS_REG		0x64	/* Status register (R) */
#define KBD_DATA_REG		0x60
#define MAX_BUFFER_SIZE     16 
#define KBD_STAT_MOUSE_OBF	0x20	/* Mouse output buffer full */
#define DEFINE_SPINLOCK(x)    spinlock_t x = __SPIN_LOCK_UNLOCKED(x)

MODULE_AUTHOR("Manasseh M. Banda."); 
MODULE_LICENSE("Dual BSD/GPL"); 

static spinlock_t the_lock;
static DEFINE_SPINLOCK(the_lock);
static int kbd_exists;
static int kbd_last_ret;
static struct workqueue_struct * my_workqueue;
static char buffer[MAX_BUFFER_SIZE];
static int in = 0;
static int out = 0;
static int bufferLength = 0;
static struct proc_dir_entry * ent;

u_short plain_map[NR_KEYS] = {
	0xf200,	0xf01b,	0xf031,	0xf032,	0xf033,	0xf034,	0xf035,	0xf036,
	0xf037,	0xf038,	0xf039,	0xf030,	0xf02d,	0xf03d,	0xf07f,	0xf009,
	0xfb71,	0xfb77,	0xfb65,	0xfb72,	0xfb74,	0xfb79,	0xfb75,	0xfb69,
	0xfb6f,	0xfb70,	0xf05b,	0xf05d,	0xf201,	0xf702,	0xfb61,	0xfb73,
	0xfb64,	0xfb66,	0xfb67,	0xfb68,	0xfb6a,	0xfb6b,	0xfb6c,	0xf03b,
	0xf027,	0xf060,	0xf700,	0xf05c,	0xfb7a,	0xfb78,	0xfb63,	0xfb76,
	0xfb62,	0xfb6e,	0xfb6d,	0xf02c,	0xf02e,	0xf02f,	0xf700,	0xf30c,
	0xf703,	0xf020,	0xf207,	0xf100,	0xf101,	0xf102,	0xf103,	0xf104,
	0xf105,	0xf106,	0xf107,	0xf108,	0xf109,	0xf208,	0xf209,	0xf307,
	0xf308,	0xf309,	0xf30b,	0xf304,	0xf305,	0xf306,	0xf30a,	0xf301,
	0xf302,	0xf303,	0xf300,	0xf310,	0xf206,	0xf200,	0xf03c,	0xf10a,
	0xf10b,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,
	0xf30e,	0xf702,	0xf30d,	0xf01c,	0xf701,	0xf205,	0xf114,	0xf603,
	0xf118,	0xf601,	0xf602,	0xf117,	0xf600,	0xf119,	0xf115,	0xf116,
	0xf11a,	0xf10c,	0xf10d,	0xf11b,	0xf11c,	0xf110,	0xf311,	0xf11d,
	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,
};

u_short shift_map[NR_KEYS] = {
	0xf200,	0xf01b,	0xf021,	0xf040,	0xf023,	0xf024,	0xf025,	0xf05e,
	0xf026,	0xf02a,	0xf028,	0xf029,	0xf05f,	0xf02b,	0xf07f,	0xf009,
	0xfb51,	0xfb57,	0xfb45,	0xfb52,	0xfb54,	0xfb59,	0xfb55,	0xfb49,
	0xfb4f,	0xfb50,	0xf07b,	0xf07d,	0xf201,	0xf702,	0xfb41,	0xfb53,
	0xfb44,	0xfb46,	0xfb47,	0xfb48,	0xfb4a,	0xfb4b,	0xfb4c,	0xf03a,
	0xf022,	0xf07e,	0xf700,	0xf07c,	0xfb5a,	0xfb58,	0xfb43,	0xfb56,
	0xfb42,	0xfb4e,	0xfb4d,	0xf03c,	0xf03e,	0xf03f,	0xf700,	0xf30c,
	0xf703,	0xf020,	0xf207,	0xf10a,	0xf10b,	0xf10c,	0xf10d,	0xf10e,
	0xf10f,	0xf110,	0xf111,	0xf112,	0xf113,	0xf213,	0xf203,	0xf307,
	0xf308,	0xf309,	0xf30b,	0xf304,	0xf305,	0xf306,	0xf30a,	0xf301,
	0xf302,	0xf303,	0xf300,	0xf310,	0xf206,	0xf200,	0xf03e,	0xf10a,
	0xf10b,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,
	0xf30e,	0xf702,	0xf30d,	0xf200,	0xf701,	0xf205,	0xf114,	0xf603,
	0xf20b,	0xf601,	0xf602,	0xf117,	0xf600,	0xf20a,	0xf115,	0xf116,
	0xf11a,	0xf10c,	0xf10d,	0xf11b,	0xf11c,	0xf110,	0xf311,	0xf11d,
	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,
};

ushort *key_maps[MAX_NR_KEYMAPS] = {
	plain_map, shift_map
};

struct worker_data{
    int character;
    struct work_struct task;
};

int kdb_get_kbd_char(void){
	int scancode, scanstatus;
	static int shift_lock;	/* CAPS LOCK state (0-off, 1-on) */
	static int shift_key;	/* Shift next keypress */
	u_short keychar;

	kbd_exists = 1;

	if (inb(KBD_STATUS_REG) == 0)
		return -1;

	/*
	 * Fetch the scancode
	 */
	scancode = inb(KBD_DATA_REG);
	scanstatus = inb(KBD_STATUS_REG);

	/*
	 * Ignore mouse events.
	 */
	if (scanstatus & KBD_STAT_MOUSE_OBF)
		return -1;


	/*
	 * Ignore release, trigger on make
	 * (except for shift keys, where we want to
	 *  keep the shift state so long as the key is
	 *  held down).
	 */

	if (((scancode&0x7f) == 0x2a) || ((scancode&0x7f) == 0x36)) {
		/*
		 * Next key may use shift table
		 */
		if ((scancode & 0x80) == 0)
			shift_key = 1;
		else
			shift_key = 0;
		return -1;
	}

	if ((scancode&0x7f) == 0x1d){
		return -1;
	}

	if ((scancode & 0x80) != 0) {
		if (scancode == 0x9c)
			kbd_last_ret = 0;
		return -1;
	}

	scancode &= 0x7f;

	/*
	 * Translate scancode
	 */

	if (scancode == 0x3a) {
		/*
		 * Toggle caps lock
		 */
		shift_lock ^= 1;

#ifdef	KDB_BLINK_LED
		kdb_toggleled(0x4);
#endif
		return -1;
	}

	if (scancode == 0x0e) {
		/*
		 * Backspace
		 */
		return 8;
	}

	/* Special Key */
	switch (scancode) {
	case 0xF: /* Tab */
		return 9;
	case 0x53: /* Del */
		return 4;
	case 0x47: /* Home */
		return 1;
	case 0x4F: /* End */
		return 5;
	case 0x4B: /* Left */
		return 2;
	case 0x48: /* Up */
		return 16;
	case 0x50: /* Down */
		return 14;
	case 0x4D: /* Right */
		return 6;
	}

	if (scancode == 0xe0)
		return -1;
	if (scancode == 0x73)
		scancode = 0x59;
	else if (scancode == 0x7d)
		scancode = 0x7c;

	if (!shift_lock && !shift_key) {
		keychar = plain_map[scancode];
	} else if ((shift_lock || shift_key) && key_maps[1]) {
		keychar = key_maps[1][scancode];
	} else {
		keychar = 0x0020;
	}
	keychar &= 0x0fff;
	if (keychar == '\t')
		keychar = ' ';
	switch (KTYP(keychar)) {
	case KT_LETTER:
	case KT_LATIN:
		if (isprint(keychar))
			break;		/* printable characters */
		/* fall through */
	case KT_SPEC:
		if (keychar == K_ENTER)
			break;
		/* fall through */
	default:
		return -1;	/* ignore unprintables */
	}

	if (scancode == 0x1c) {
		kbd_last_ret = 1;
		return 13;
	}

	return keychar & 0xff;
}



static ssize_t read_buffer(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) {
	char buf[MAX_BUFFER_SIZE];
    int len = 0;
	int num = 0;

    if(*ppos > 0 || count < MAX_BUFFER_SIZE){
        return 0;
    }
	
	spin_lock(&the_lock);
	while(num < bufferLength){
		buf[num] = buffer[out];
		out = (out+1)%MAX_BUFFER_SIZE;
		num++;
		len++;
	}
	bufferLength = 0;
	num = 0;
	spin_unlock(&the_lock);

    if(copy_to_user(ubuf,buf,len)){
        return -EFAULT;
    }

    *ppos = len;
    return len;
}

static void write_to_buffer(struct work_struct * task){
    struct worker_data * data = container_of(task, struct worker_data, task);
	if(data -> character != -1){
		char c = data->character;
		if(bufferLength < MAX_BUFFER_SIZE){
			if(c == '\015'){
				c = '\n';
			}
			spin_lock(&the_lock);
			buffer[in] = c;
			bufferLength++;
			in = (in + 1) % MAX_BUFFER_SIZE;
			spin_unlock(&the_lock);
		}
	}
    kfree(data);
}

static irqreturn_t irq_handler(int irq, void *dev_id){
    struct worker_data * data;
    data = (struct worker_data *)kmalloc(sizeof(struct worker_data), GFP_ATOMIC);
    data->character = kdb_get_kbd_char();

    INIT_WORK(&data->task, write_to_buffer);
    schedule_work(&data->task);

    return IRQ_HANDLED;
}

static struct file_operations myops = {
    .owner = THIS_MODULE,
    .read = read_buffer,
};

static int driver_init(void){
	ent = proc_create("keybuff", 0660, NULL, &myops);
    my_workqueue = create_workqueue(MY_WORK_QUEUE_NAME);

    return request_irq(1, irq_handler, IRQF_SHARED, "keyboard_irq_handler", (void*)irq_handler);
}

static void driver_cleanup(void){
    free_irq(1, (void *)irq_handler);
	proc_remove(ent);
}

module_init(driver_init);
module_exit(driver_cleanup);