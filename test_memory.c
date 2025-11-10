#include "lib/headers/memory_manager.h"
#include "lib/ssh_chatter_sync.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf("Testing memory manager...\n");
    
    // Initialize
    GC_INIT();
    ssh_chatter_sync_init();
    
    // Create a context
    sshc_memory_context_t *ctx = sshc_memory_context_create("test");
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create memory context\n");
        return 1;
    }
    
    // Push the context
    sshc_memory_context_t *prev = sshc_memory_context_push(ctx);
    
    // Allocate some memory
    void *ptr1 = GC_MALLOC(100);
    void *ptr2 = GC_CALLOC(10, 20);
    
    if (ptr1 == NULL || ptr2 == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    
    printf("Allocated memory successfully\n");
    
    // Pop the context
    sshc_memory_context_pop(prev);
    
    // Destroy the context (should free all allocations)
    sshc_memory_context_destroy(ctx);
    
    // Cleanup
    ssh_chatter_sync_stop();
    ssh_chatter_sync_free_history();
    sshc_memory_runtime_shutdown();
    
    printf("Test completed successfully\n");
    return 0;
}
