#pragma once
#include <vulkan/vulkan.h>
#include <cstdint>
#include <cstring>

namespace genesis {
// Offscreen homebrew transfer. Every handle belongs to this probe's device.
struct ProbeResources {
    VkDevice device{};
    VkCommandPool pool{};
    VkFence fence{};
    VkBuffer buffer{};
    VkDeviceMemory memory{};
    ~ProbeResources() {
        if (!device) return;
        if (fence) vkDestroyFence(device,fence,nullptr);
        if (pool) vkDestroyCommandPool(device,pool,nullptr);
        if (buffer) vkDestroyBuffer(device,buffer,nullptr);
        if (memory) vkFreeMemory(device,memory,nullptr);
        vkDestroyDevice(device,nullptr);
    }
};

inline const char* verifyTransfer(VkPhysicalDevice gpu,uint32_t family) {
    constexpr VkDeviceSize length=256;
    constexpr uint32_t pattern=0x78a11e42;
    ProbeResources r;
    float priority=1;
    VkDeviceQueueCreateInfo queueInfo{};
    queueInfo.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueInfo.queueFamilyIndex=family;
    queueInfo.queueCount=1;
    queueInfo.pQueuePriorities=&priority;
    VkDeviceCreateInfo deviceInfo{};
    deviceInfo.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceInfo.queueCreateInfoCount=1;
    deviceInfo.pQueueCreateInfos=&queueInfo;
    if(vkCreateDevice(gpu,&deviceInfo,nullptr,&r.device)!=VK_SUCCESS)return "device creation failed";
    VkBufferCreateInfo buffer{};
    buffer.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buffer.size=length;
    buffer.usage=VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    if(vkCreateBuffer(r.device,&buffer,nullptr,&r.buffer)!=VK_SUCCESS)return "buffer creation failed";
    VkMemoryRequirements size;
    vkGetBufferMemoryRequirements(r.device,r.buffer,&size);
    VkPhysicalDeviceMemoryProperties types;
    vkGetPhysicalDeviceMemoryProperties(gpu,&types);
    uint32_t type=0;
    while(type<types.memoryTypeCount && (!(size.memoryTypeBits&(1u<<type)) ||
        !(types.memoryTypes[type].propertyFlags&VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT))) ++type;
    if(type==types.memoryTypeCount)return "host-visible buffer unavailable";
    VkMemoryAllocateInfo alloc{};
    alloc.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc.memoryTypeIndex=type;
    alloc.allocationSize=size.size;
    if(vkAllocateMemory(r.device,&alloc,nullptr,&r.memory)!=VK_SUCCESS ||
       vkBindBufferMemory(r.device,r.buffer,r.memory,0)!=VK_SUCCESS)return "buffer allocation failed";
    VkCommandPoolCreateInfo pool{};
    pool.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool.queueFamilyIndex=family;
    if(vkCreateCommandPool(r.device,&pool,nullptr,&r.pool)!=VK_SUCCESS)return "command pool failed";
    VkCommandBufferAllocateInfo cmdInfo{};
    cmdInfo.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cmdInfo.commandPool=r.pool;
    cmdInfo.commandBufferCount=1;
    VkCommandBuffer cmd{};
    if(vkAllocateCommandBuffers(r.device,&cmdInfo,&cmd)!=VK_SUCCESS)return "command allocation failed";
    VkCommandBufferBeginInfo begin{};
    begin.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    if(vkBeginCommandBuffer(cmd,&begin)!=VK_SUCCESS)return "command begin failed";
    vkCmdFillBuffer(cmd,r.buffer,0,length,pattern);
    VkMemoryBarrier barrier{};
    barrier.sType=VK_STRUCTURE_TYPE_MEMORY_BARRIER;
    barrier.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
    barrier.dstAccessMask=VK_ACCESS_HOST_READ_BIT;
    vkCmdPipelineBarrier(cmd,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_HOST_BIT,0,1,&barrier,0,nullptr,0,nullptr);
    if(vkEndCommandBuffer(cmd)!=VK_SUCCESS)return "command encoding failed";
    VkFenceCreateInfo fence{};
    fence.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    if(vkCreateFence(r.device,&fence,nullptr,&r.fence)!=VK_SUCCESS)return "fence creation failed";
    VkQueue queue;
    vkGetDeviceQueue(r.device,family,0,&queue);
    VkSubmitInfo submit{};
    submit.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.commandBufferCount=1;
    submit.pCommandBuffers=&cmd;
    if(vkQueueSubmit(queue,1,&submit,r.fence)!=VK_SUCCESS)return "queue submission failed";
    if(vkWaitForFences(r.device,1,&r.fence,VK_TRUE,UINT64_MAX)!=VK_SUCCESS) {
        vkDeviceWaitIdle(r.device);
        return "fence wait failed";
    }
    void* mapped=nullptr;
    if(vkMapMemory(r.device,r.memory,0,VK_WHOLE_SIZE,0,&mapped)!=VK_SUCCESS)return "host mapping failed";
    VkMappedMemoryRange range{};
    range.sType=VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE;
    range.memory=r.memory;
    range.size=VK_WHOLE_SIZE;
    bool ok=vkInvalidateMappedMemoryRanges(r.device,1,&range)==VK_SUCCESS;
    for(size_t i=0;ok && i<length;i+=sizeof(pattern)) {
        uint32_t word;
        std::memcpy(&word,static_cast<char*>(mapped)+i,sizeof(word));
        ok=word==pattern;
    }
    vkUnmapMemory(r.device,r.memory);
    return ok?"PASS (256 verified bytes)":"readback failed";
}
}
