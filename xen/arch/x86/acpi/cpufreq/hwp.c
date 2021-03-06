/*
 * hwp.c cpufreq driver to run Intel Hardware P-States (HWP)
 *
 * Copyright (C) 2021 Jason Andryuk <jandryuk@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/cpumask.h>
#include <xen/init.h>
#include <xen/param.h>
#include <xen/xmalloc.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <acpi/cpufreq/cpufreq.h>

static bool feature_hwp;
static bool feature_hwp_notification;
static bool feature_hwp_activity_window;
static bool feature_hwp_energy_perf;
static bool feature_hwp_pkg_level_ctl;
static bool feature_hwp_peci;

static bool feature_hdc;
static bool feature_fast_msr;

bool opt_hwp = true;
boolean_param("hwp", opt_hwp);

union hwp_request
{
    struct
    {
        uint64_t min_perf:8;
        uint64_t max_perf:8;
        uint64_t desired:8;
        uint64_t energy_perf:8;
        uint64_t activity_window:10;
        uint64_t package_control:1;
        uint64_t reserved:16;
        uint64_t activity_window_valid:1;
        uint64_t energy_perf_valid:1;
        uint64_t desired_valid:1;
        uint64_t max_perf_valid:1;
        uint64_t min_perf_valid:1;
    };
    uint64_t raw;
};

struct hwp_drv_data
{
    union
    {
        uint64_t hwp_caps;
        struct
        {
            uint64_t hw_highest:8;
            uint64_t hw_guaranteed:8;
            uint64_t hw_most_efficient:8;
            uint64_t hw_lowest:8;
            uint64_t hw_reserved:32;
        };
    };
    union hwp_request curr_req;
    uint16_t activity_window;
    uint8_t minimum;
    uint8_t maximum;
    uint8_t desired;
    uint8_t energy_perf;
};
struct hwp_drv_data *hwp_drv_data[NR_CPUS];

#define hwp_err(...)     printk(XENLOG_ERR __VA_ARGS__)
#define hwp_info(...)    printk(XENLOG_INFO __VA_ARGS__)
#define hwp_verbose(...)                   \
({                                         \
    if ( cpufreq_verbose )                 \
    {                                      \
        printk(XENLOG_DEBUG __VA_ARGS__);  \
    }                                      \
})
#define hwp_verbose_cont(...)              \
({                                         \
    if ( cpufreq_verbose )                 \
    {                                      \
        printk(             __VA_ARGS__);  \
    }                                      \
})

static int hwp_governor(struct cpufreq_policy *policy,
                        unsigned int event)
{
    int ret;

    if ( policy == NULL )
        return -EINVAL;

    switch (event)
    {
    case CPUFREQ_GOV_START:
        ret = 0;
        break;
    case CPUFREQ_GOV_STOP:
        ret = -EINVAL;
        break;
    case CPUFREQ_GOV_LIMITS:
        ret = 0;
        break;
    default:
        ret = -EINVAL;
    }

    return ret;
}

static struct cpufreq_governor hwp_cpufreq_governor =
{
    .name          = "hwp-internal",
    .governor      = hwp_governor,
};

static int __init cpufreq_gov_hwp_init(void)
{
    return cpufreq_register_governor(&hwp_cpufreq_governor);
}
__initcall(cpufreq_gov_hwp_init);

bool hwp_available(void)
{
    uint32_t eax;
    uint64_t val;
    bool use_hwp;

    if ( boot_cpu_data.cpuid_level < CPUID_PM_LEAF )
    {
        hwp_verbose("cpuid_level (%u) lacks HWP support\n", boot_cpu_data.cpuid_level);

        return false;
    }

    eax = cpuid_eax(CPUID_PM_LEAF);
    feature_hwp                 = !!(eax & CPUID6_EAX_HWP);
    feature_hwp_notification    = !!(eax & CPUID6_EAX_HWP_Notification);
    feature_hwp_activity_window = !!(eax & CPUID6_EAX_HWP_Activity_Window);
    feature_hwp_energy_perf     =
        !!(eax & CPUID6_EAX_HWP_Energy_Performance_Preference);
    feature_hwp_pkg_level_ctl   =
        !!(eax & CPUID6_EAX_HWP_Package_Level_Request);
    feature_hwp_peci            = !!(eax & CPUID6_EAX_HWP_PECI);

    hwp_verbose("HWP: %d notify: %d act_window: %d energy_perf: %d pkg_level: %d peci: %d\n",
                feature_hwp, feature_hwp_notification,
                feature_hwp_activity_window, feature_hwp_energy_perf,
                feature_hwp_pkg_level_ctl, feature_hwp_peci);

    if ( !feature_hwp )
    {
        hwp_verbose("Hardware does not support HWP\n");

        return false;
    }

    if ( boot_cpu_data.cpuid_level < 0x16 )
    {
        hwp_info("HWP disabled: cpuid_level %x < 0x16 lacks CPU freq info\n",
                 boot_cpu_data.cpuid_level);

        return false;
    }

    hwp_verbose("HWP: FAST_IA32_HWP_REQUEST %ssupported\n",
                eax & CPUID6_EAX_FAST_HWP_MSR ? "" : "not ");
    if ( eax & CPUID6_EAX_FAST_HWP_MSR )
    {
        if ( rdmsr_safe(MSR_FAST_UNCORE_MSRS_CAPABILITY, val) )
            hwp_err("error rdmsr_safe(MSR_FAST_UNCORE_MSRS_CAPABILITY)\n");

        hwp_verbose("HWP: MSR_FAST_UNCORE_MSRS_CAPABILITY: %016lx\n", val);
        if (val & FAST_IA32_HWP_REQUEST )
        {
            hwp_verbose("HWP: FAST_IA32_HWP_REQUEST MSR available\n");
            feature_fast_msr = true;
        }
    }

    feature_hdc = !!(eax & CPUID6_EAX_HDC);

    hwp_verbose("HWP: Hardware Duty Cycling (HDC) %ssupported\n",
                feature_hdc ? "" : "not ");

    hwp_verbose("HWP: HW_FEEDBACK %ssupported\n",
                (eax & CPUID6_EAX_HW_FEEDBACK) ? "" : "not ");

    use_hwp = feature_hwp && opt_hwp;
    cpufreq_governor_internal = use_hwp;

    if ( use_hwp )
        hwp_info("Using HWP for cpufreq\n");

    return use_hwp;
}

static void hdc_set_pkg_hdc_ctl(bool val)
{
    uint64_t msr;

    if ( rdmsr_safe(MSR_IA32_PKG_HDC_CTL, msr) )
    {
        hwp_err("error rdmsr_safe(MSR_IA32_PKG_HDC_CTL)\n");

        return;
    }

    msr = val ? IA32_PKG_HDC_CTL_HDC_PKG_Enable : 0;

    if ( wrmsr_safe(MSR_IA32_PKG_HDC_CTL, msr) )
        hwp_err("error wrmsr_safe(MSR_IA32_PKG_HDC_CTL): %016lx\n", msr);
}

static void hdc_set_pm_ctl1(bool val)
{
    uint64_t msr;

    if ( rdmsr_safe(MSR_IA32_PM_CTL1, msr) )
    {
        hwp_err("error rdmsr_safe(MSR_IA32_PM_CTL1)\n");

        return;
    }

    msr = val ? IA32_PM_CTL1_HDC_Allow_Block : 0;

    if ( wrmsr_safe(MSR_IA32_PM_CTL1, msr) )
        hwp_err("error wrmsr_safe(MSR_IA32_PM_CTL1): %016lx\n", msr);
}

static void hwp_fast_uncore_msrs_ctl(bool val)
{
    uint64_t msr;

    if ( rdmsr_safe(MSR_FAST_UNCORE_MSRS_CTL, msr) )
        hwp_err("error rdmsr_safe(MSR_FAST_UNCORE_MSRS_CTL)\n");

    msr = val;

    if ( wrmsr_safe(MSR_FAST_UNCORE_MSRS_CTL, msr) )
        hwp_err("error wrmsr_safe(MSR_FAST_UNCORE_MSRS_CTL): %016lx\n", msr);
}

static void hwp_get_cpu_speeds(struct cpufreq_policy *policy)
{
    uint32_t base_khz, max_khz, bus_khz, edx;

    cpuid(0x16, &base_khz, &max_khz, &bus_khz, &edx);

    /* aperf/mperf scales base. */
    policy->cpuinfo.perf_freq = base_khz * 1000;
    policy->cpuinfo.min_freq = base_khz * 1000;
    policy->cpuinfo.max_freq = max_khz * 1000;
    policy->min = base_khz * 1000;
    policy->max = max_khz * 1000;
    policy->cur = 0;
}

static void hwp_read_capabilities(void *info)
{
    struct cpufreq_policy *policy = info;
    struct hwp_drv_data *data = hwp_drv_data[policy->cpu];

    if ( rdmsr_safe(MSR_IA32_HWP_CAPABILITIES, data->hwp_caps) )
    {
        hwp_err("CPU%u: error rdmsr_safe(MSR_IA32_HWP_CAPABILITIES)\n",
                policy->cpu);

        return;
    }

    if ( rdmsr_safe(MSR_IA32_HWP_REQUEST, data->curr_req.raw) )
    {
        hwp_err("CPU%u: error rdmsr_safe(MSR_IA32_HWP_REQUEST)\n", policy->cpu);

        return;
    }
}

static void hwp_init_msrs(void *info)
{
    struct cpufreq_policy *policy = info;
    uint64_t val;

    /* Package level MSR, but we don't have a good idea of packages here, so
     * just do it everytime. */
    if ( rdmsr_safe(MSR_IA32_PM_ENABLE, val) )
    {
        hwp_err("CPU%u: error rdmsr_safe(MSR_IA32_PM_ENABLE)\n", policy->cpu);

        return;
    }

    hwp_verbose("CPU%u: MSR_IA32_PM_ENABLE: %016lx\n", policy->cpu, val);
    if ( val != IA32_PM_ENABLE_HWP_ENABLE )
    {
        val = IA32_PM_ENABLE_HWP_ENABLE;
        if ( wrmsr_safe(MSR_IA32_PM_ENABLE, val) )
            hwp_err("CPU%u: error wrmsr_safe(MSR_IA32_PM_ENABLE, %lx)\n",
                    policy->cpu, val);
    }

    hwp_read_capabilities(info);

    /* Check for APERF/MPERF support in hardware
     * also check for boost/turbo support */
    intel_feature_detect(policy);

    if ( feature_hdc )
    {
        hdc_set_pkg_hdc_ctl(true);
        hdc_set_pm_ctl1(true);
    }

    if ( feature_fast_msr )
        hwp_fast_uncore_msrs_ctl(true);

    hwp_get_cpu_speeds(policy);
}

static int hwp_cpufreq_verify(struct cpufreq_policy *policy)
{
    unsigned int cpu = policy->cpu;
    struct hwp_drv_data *data = hwp_drv_data[cpu];

    if ( !feature_hwp_energy_perf && data->energy_perf )
    {
        if ( data->energy_perf > 15 )
        {
            hwp_err("energy_perf %d exceeds IA32_ENERGY_PERF_BIAS range 0-15\n",
                    data->energy_perf);

            return -EINVAL;
        }
    }

    if ( !feature_hwp_activity_window && data->activity_window )
    {
        hwp_err("HWP activity window not supported.\n");

        return -EINVAL;
    }

    return 0;
}

/* val 0 - highest performance, 15 - maximum energy savings */
static void hwp_energy_perf_bias(void *info)
{
    uint64_t msr;
    struct hwp_drv_data *data = info;
    uint8_t val = data->energy_perf;

    ASSERT(val <= 15);

    if ( rdmsr_safe(MSR_IA32_ENERGY_PERF_BIAS, msr) )
    {
        hwp_err("error rdmsr_safe(MSR_IA32_ENERGY_PERF_BIAS)\n");

        return;
    }

    msr &= ~(0xf);
    msr |= val;

    if ( wrmsr_safe(MSR_IA32_ENERGY_PERF_BIAS, msr) )
        hwp_err("error wrmsr_safe(MSR_IA32_ENERGY_PERF_BIAS): %016lx\n", msr);
}

static void hwp_write_request(void *info)
{
    struct cpufreq_policy *policy = info;
    struct hwp_drv_data *data = hwp_drv_data[policy->cpu];
    union hwp_request hwp_req = data->curr_req;

    BUILD_BUG_ON(sizeof(union hwp_request) != sizeof(uint64_t));
    if ( wrmsr_safe(MSR_IA32_HWP_REQUEST, hwp_req.raw) )
    {
        hwp_err("CPU%u: error wrmsr_safe(MSR_IA32_HWP_REQUEST, %lx)\n",
                policy->cpu, hwp_req.raw);
        rdmsr_safe(MSR_IA32_HWP_REQUEST, data->curr_req.raw);
    }
}

static int hwp_cpufreq_target(struct cpufreq_policy *policy,
                              unsigned int target_freq, unsigned int relation)
{
    unsigned int cpu = policy->cpu;
    struct hwp_drv_data *data = hwp_drv_data[cpu];
    union hwp_request hwp_req;

    /* Zero everything to ensure reserved bits are zero... */
    hwp_req.raw = 0;
    /* .. and update from there */
    hwp_req.min_perf = data->minimum;
    hwp_req.max_perf = data->maximum;
    hwp_req.desired = data->desired;
    if ( feature_hwp_energy_perf )
        hwp_req.energy_perf = data->energy_perf;
    if ( feature_hwp_activity_window )
        hwp_req.activity_window = data->activity_window;

    if ( hwp_req.raw == data->curr_req.raw )
        return 0;

    data->curr_req.raw = hwp_req.raw;

    hwp_verbose("CPU%u: wrmsr HWP_REQUEST %016lx\n", cpu, hwp_req.raw);
    on_selected_cpus(cpumask_of(cpu), hwp_write_request, policy, 1);

    if ( !feature_hwp_energy_perf && data->energy_perf )
    {
        on_selected_cpus(cpumask_of(cpu), hwp_energy_perf_bias,
                         data, 1);
    }

    return 0;
}

static int hwp_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
    unsigned int cpu = policy->cpu;
    struct hwp_drv_data *data;

    if ( cpufreq_opt_governor )
    {
        printk(XENLOG_WARNING
               "HWP: governor \"%s\" is incompatible with hwp. Using default \"%s\"\n",
               cpufreq_opt_governor->name, hwp_cpufreq_governor.name);
    }
    policy->governor = &hwp_cpufreq_governor;

    data = xzalloc(typeof(*data));
    if ( !data )
        return -ENOMEM;

    hwp_drv_data[cpu] = data;

    on_selected_cpus(cpumask_of(cpu), hwp_init_msrs, policy, 1);

    data->minimum = data->hw_lowest;
    data->maximum = data->hw_highest;
    data->desired = 0; /* default to HW autonomous */
    if ( feature_hwp_energy_perf )
        data->energy_perf = 0x80;
    else
        data->energy_perf = 7;

    hwp_verbose("CPU%u: IA32_HWP_CAPABILITIES: %016lx\n", cpu, data->hwp_caps);

    hwp_verbose("CPU%u: rdmsr HWP_REQUEST %016lx\n", cpu, data->curr_req.raw);

    return 0;
}

static int hwp_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
    unsigned int cpu = policy->cpu;

    xfree(hwp_drv_data[cpu]);
    hwp_drv_data[cpu] = NULL;

    return 0;
}

/* The SDM reads like turbo should be disabled with MSR_IA32_PERF_CTL and
 * PERF_CTL_TURBO_DISENGAGE, but that does not seem to actually work, at least
 * with my HWP testing.  MSR_IA32_MISC_ENABLE and MISC_ENABLE_TURBO_DISENGAGE
 * is what Linux uses and seems to work. */
static void hwp_set_misc_turbo(void *info)
{
    struct cpufreq_policy *policy = info;
    uint64_t msr;

    if ( rdmsr_safe(MSR_IA32_MISC_ENABLE, msr) )
    {
        hwp_err("CPU%u: error rdmsr_safe(MSR_IA32_MISC_ENABLE)\n", policy->cpu);

        return;
    }

    if ( policy->turbo == CPUFREQ_TURBO_ENABLED )
        msr &= ~MSR_IA32_MISC_ENABLE_TURBO_DISENGAGE;
    else
        msr |= MSR_IA32_MISC_ENABLE_TURBO_DISENGAGE;

    if ( wrmsr_safe(MSR_IA32_MISC_ENABLE, msr) )
        hwp_err("CPU%u: error wrmsr_safe(MSR_IA32_MISC_ENABLE): %016lx\n",
                policy->cpu, msr);
}

static int hwp_cpufreq_update(int cpuid, struct cpufreq_policy *policy)
{
    on_selected_cpus(cpumask_of(cpuid), hwp_set_misc_turbo, policy, 1);

    return 0;
}

static const struct cpufreq_driver __initconstrel hwp_cpufreq_driver =
{
    .name   = "hwp-cpufreq",
    .verify = hwp_cpufreq_verify,
    .target = hwp_cpufreq_target,
    .init   = hwp_cpufreq_cpu_init,
    .exit   = hwp_cpufreq_cpu_exit,
    .update = hwp_cpufreq_update,
};

int get_hwp_para(struct cpufreq_policy *policy, struct xen_hwp_para *hwp_para)
{
    unsigned int cpu = policy->cpu;
    struct hwp_drv_data *data = hwp_drv_data[cpu];

    if ( data == NULL )
        return -EINVAL;

    hwp_para->hw_feature        =
        feature_hwp_activity_window ? XEN_SYSCTL_HWP_FEAT_ACT_WINDOW  : 0 |
        feature_hwp_energy_perf     ? XEN_SYSCTL_HWP_FEAT_ENERGY_PERF : 0;
    hwp_para->hw_lowest         = data->hw_lowest;
    hwp_para->hw_most_efficient = data->hw_most_efficient;
    hwp_para->hw_guaranteed     = data->hw_guaranteed;
    hwp_para->hw_highest        = data->hw_highest;
    hwp_para->minimum           = data->minimum;
    hwp_para->maximum           = data->maximum;
    hwp_para->energy_perf       = data->energy_perf;
    hwp_para->activity_window   = data->activity_window;
    hwp_para->desired           = data->desired;

    return 0;
}

int set_hwp_para(struct cpufreq_policy *policy,
                 struct xen_set_hwp_para *set_hwp)
{
    unsigned int cpu = policy->cpu;
    struct hwp_drv_data *data = hwp_drv_data[cpu];

    if ( data == NULL )
        return -EINVAL;

    /* Validate all parameters first */
    if ( set_hwp->set_params & ~XEN_SYSCTL_HWP_SET_PARAM_MASK )
    {
        hwp_err("Invalid bits in hwp set_params %u\n",
                set_hwp->set_params);

        return -EINVAL;
    }

    if ( set_hwp->activity_window & ~XEN_SYSCTL_HWP_ACT_WINDOW_MASK )
    {
        hwp_err("Invalid bits in activity window %u\n",
                set_hwp->activity_window);

        return -EINVAL;
    }

    if ( !feature_hwp_energy_perf &&
         set_hwp->set_params & XEN_SYSCTL_HWP_SET_ENERGY_PERF &&
         set_hwp->energy_perf > 0xf )
    {
        hwp_err("energy_perf %u out of range for IA32_ENERGY_PERF_BIAS\n",
                set_hwp->energy_perf);

        return -EINVAL;
    }

    if ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_DESIRED &&
         set_hwp->desired != 0 &&
         ( set_hwp->desired < data->hw_lowest ||
           set_hwp->desired > data->hw_highest ) )
    {
        hwp_err("hwp desired %u is out of range (%u ... %u)\n",
                set_hwp->desired, data->hw_lowest, data->hw_highest);

        return -EINVAL;
    }

    /*
     * minimum & maximum are not validated as hardware doesn't seem to care
     * and the SDM says CPUs will clip internally.
     */

    /* Apply presets */
    switch ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_PRESET_MASK )
    {
    case XEN_SYSCTL_HWP_SET_PRESET_POWERSAVE:
        data->minimum = data->hw_lowest;
        data->maximum = data->hw_lowest;
        data->activity_window = 0;
        if ( feature_hwp_energy_perf )
            data->energy_perf = 0xff;
        else
            data->energy_perf = 0xf;
        data->desired = 0;
        break;
    case XEN_SYSCTL_HWP_SET_PRESET_PERFORMANCE:
        data->minimum = data->hw_highest;
        data->maximum = data->hw_highest;
        data->activity_window = 0;
        data->energy_perf = 0;
        data->desired = 0;
        break;
    case XEN_SYSCTL_HWP_SET_PRESET_BALANCE:
        data->minimum = data->hw_lowest;
        data->maximum = data->hw_highest;
        data->activity_window = 0;
        data->energy_perf = 0x80;
        if ( feature_hwp_energy_perf )
            data->energy_perf = 0x80;
        else
            data->energy_perf = 0x7;
        data->desired = 0;
        break;
    case XEN_SYSCTL_HWP_SET_PRESET_NONE:
        break;
    default:
        printk("HWP: Invalid preset value: %u\n",
               set_hwp->set_params & XEN_SYSCTL_HWP_SET_PRESET_MASK);

        return -EINVAL;
    }

    /* Further customize presets if needed */
    if ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_MINIMUM )
        data->minimum = set_hwp->minimum;

    if ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_MAXIMUM )
        data->maximum = set_hwp->maximum;

    if ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_ENERGY_PERF )
        data->energy_perf = set_hwp->energy_perf;

    if ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_DESIRED )
        data->desired = set_hwp->desired;

    if ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_ACT_WINDOW )
        data->activity_window = set_hwp->activity_window &
                                XEN_SYSCTL_HWP_ACT_WINDOW_MASK;

    hwp_cpufreq_target(policy, 0, 0);

    return 0;
}

int hwp_register_driver(void)
{
    int ret;

    ret = cpufreq_register_driver(&hwp_cpufreq_driver);

    return ret;
}
