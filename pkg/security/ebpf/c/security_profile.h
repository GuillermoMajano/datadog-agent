#ifndef _SECURITY_PROFILE_H_
#define _SECURITY_PROFILE_H_

__attribute__((always_inline)) u64 is_send_signal_available() {
    u64 send_signal;
    LOAD_CONSTANT("send_signal", send_signal);
    return send_signal;
};

enum security_profile_state {
    UNKNOWN,
    ALERT,
    KILL,
};

struct security_profile_t {
    u64 cookie;
    u32 state;
};

struct bpf_map_def SEC("maps/security_profiles") security_profiles = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct container_context_t),
    .value_size = sizeof(struct security_profile_t),
    .max_entries = 1, // will be overridden at runtime
};

struct security_profile_syscalls_t {
    char syscalls[SYSCALL_ENCODING_TABLE_SIZE];
};

struct bpf_map_def SEC("maps/security_profile_syscalls") security_profile_syscalls = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct security_profile_syscalls_t),
    .max_entries = 1, // will be overridden at runtime
};

__attribute__((always_inline)) void evaluate_security_profile_syscalls(void *args, struct syscall_monitor_event_t *event, long syscall_id) {
    // lookup security profile
    struct security_profile_t *profile = bpf_map_lookup_elem(&security_profiles, &event->container);
    if (profile == NULL) {
        // this workload doesn't have a profile, ignore
        return;
    }

    // lookup the syscalls in this profile
    struct security_profile_syscalls_t *syscalls = bpf_map_lookup_elem(&security_profile_syscalls, &profile->cookie);
    if (syscalls == NULL) {
        // should never happen, ignore
        return;
    }

    // compute the offset of the current syscall
    u16 index = ((unsigned long) syscall_id) / 8;
    u8 bit = 1 << (((unsigned long) syscall_id) % 8);
    if ((syscalls->syscalls[index & (SYSCALL_ENCODING_TABLE_SIZE - 1)] & bit) == bit) {
        // all good
        return;
    }

    // this syscall isn't allowed
    event->syscall_data.syscall_id = syscall_id;

    // remove last_sent and dirty from the event size, we don't care about these fields
    send_event_with_size_ptr(args, EVENT_ANOMALY_DETECTION_SYSCALL, event, offsetof(struct syscall_monitor_event_t, syscall_data) + sizeof(event->syscall_data.syscall_id));

    // reset syscall id in case we're also dumping this workload
    event->syscall_data.syscall_id = 0;

    if (profile->state == KILL) {
        if (is_send_signal_available()) {
            bpf_send_signal(9); // SIGKILL
        }
    }
}

#endif
