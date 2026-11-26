#pragma once
#include "scarlett_gpu.hpp"
#include "scarlett_shader.hpp"
#include "scarlett_vertex_spv.hpp"
#include <vulkan/vulkan.h>
#include <array>
#include <string>
#include <cstring>

namespace genesis {

class ScarlettVulkan {
public:
    using Handle=ScarlettGpu::Handle;
    using Command=ScarlettGpu::Command;
    using Opcode=ScarlettGpu::Opcode;

private:
    struct Buffer {
        VkBuffer buffer{};
        VkDeviceMemory memory{};
        uint64_t size=0;
        VkDeviceSize allocationSize=0;
        void* mapped=nullptr;
    };


    struct RenderTarget {
        VkDevice device{};
        VkImage image{};
        VkDeviceMemory memory{};
        VkImageView view{};
        VkRenderPass pass{};
        VkFramebuffer framebuffer{};
        VkPipelineLayout layout{};
        VkPipeline pipeline{};
        VkShaderModule vertex{};
        VkShaderModule fragment{};

        explicit RenderTarget(VkDevice d):device(d){}
        RenderTarget(const RenderTarget&)=delete;
        RenderTarget& operator=(const RenderTarget&)=delete;

        ~RenderTarget(){
            if(pipeline)
                vkDestroyPipeline(device,pipeline,nullptr);
            if(layout)
                vkDestroyPipelineLayout(device,layout,nullptr);
            if(vertex)
                vkDestroyShaderModule(device,vertex,nullptr);
            if(fragment)
                vkDestroyShaderModule(device,fragment,nullptr);
            if(framebuffer)
                vkDestroyFramebuffer(device,framebuffer,nullptr);
            if(pass)
                vkDestroyRenderPass(device,pass,nullptr);
            if(view)
                vkDestroyImageView(device,view,nullptr);
            if(image)
                vkDestroyImage(device,image,nullptr);
            if(memory)
                vkFreeMemory(device,memory,nullptr);
        }
    };

    uint32_t findMemoryType(
        uint32_t bits,
        VkMemoryPropertyFlags flags) const {
        for(uint32_t i=0;i<memoryTypes.memoryTypeCount;++i){
            if((bits&(1u<<i)) &&
               (memoryTypes.memoryTypes[i].propertyFlags
                &flags)==flags)
                return i;
        }
        return UINT32_MAX;
    }

    bool createShader(
        std::span<const uint32_t> words,
        VkShaderModule& module) {
        if(words.size()<5 ||
           words[0]!=0x07230203 ||
           words.size()>262144)
            return false;

        VkShaderModuleCreateInfo info{};
        info.sType=
            VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
        info.codeSize=words.size_bytes();
        info.pCode=words.data();

        return vkCreateShaderModule(
            device,&info,nullptr,&module)==VK_SUCCESS;
    }


    bool createRenderTarget(
        RenderTarget& t,
        uint32_t width,
        uint32_t height) {

        if(!ready || !width || !height ||
           width>2048 || height>2048)
            return false;

        constexpr VkFormat format=
            VK_FORMAT_R32G32B32A32_SFLOAT;

        VkFormatProperties props{};
        vkGetPhysicalDeviceFormatProperties(
            physical,format,&props);

        constexpr auto required=
            VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BIT |
            VK_FORMAT_FEATURE_TRANSFER_SRC_BIT;

        if((props.optimalTilingFeatures & required)
           !=required)
            return false;

        VkImageCreateInfo ii{};
        ii.sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
        ii.imageType=VK_IMAGE_TYPE_2D;
        ii.format=format;
        ii.extent={width,height,1};
        ii.mipLevels=1;
        ii.arrayLayers=1;
        ii.samples=VK_SAMPLE_COUNT_1_BIT;
        ii.tiling=VK_IMAGE_TILING_OPTIMAL;
        ii.usage=
            VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT |
            VK_IMAGE_USAGE_TRANSFER_SRC_BIT;
        ii.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
        ii.initialLayout=VK_IMAGE_LAYOUT_UNDEFINED;

        if(vkCreateImage(device,&ii,nullptr,&t.image)
           !=VK_SUCCESS)return false;

        VkMemoryRequirements req{};
        vkGetImageMemoryRequirements(
            device,t.image,&req);

        auto type=findMemoryType(
            req.memoryTypeBits,
            VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);

        if(type==UINT32_MAX)return false;

        VkMemoryAllocateInfo ai{};
        ai.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        ai.allocationSize=req.size;
        ai.memoryTypeIndex=type;

        if(vkAllocateMemory(
            device,&ai,nullptr,&t.memory)!=VK_SUCCESS)
            return false;

        if(vkBindImageMemory(
            device,t.image,t.memory,0)!=VK_SUCCESS)
            return false;

        VkImageViewCreateInfo vi{};
        vi.sType=VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
        vi.image=t.image;
        vi.viewType=VK_IMAGE_VIEW_TYPE_2D;
        vi.format=format;
        vi.subresourceRange={
            VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1
        };

        if(vkCreateImageView(
            device,&vi,nullptr,&t.view)!=VK_SUCCESS)
            return false;

        VkAttachmentDescription attachment{};
        attachment.format=format;
        attachment.samples=VK_SAMPLE_COUNT_1_BIT;
        attachment.loadOp=VK_ATTACHMENT_LOAD_OP_CLEAR;
        attachment.storeOp=VK_ATTACHMENT_STORE_OP_STORE;
        attachment.stencilLoadOp=
            VK_ATTACHMENT_LOAD_OP_DONT_CARE;
        attachment.stencilStoreOp=
            VK_ATTACHMENT_STORE_OP_DONT_CARE;
        attachment.initialLayout=
            VK_IMAGE_LAYOUT_UNDEFINED;
        attachment.finalLayout=
            VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;

        VkAttachmentReference ref{
            0,VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL
        };

        VkSubpassDescription sub{};
        sub.pipelineBindPoint=
            VK_PIPELINE_BIND_POINT_GRAPHICS;
        sub.colorAttachmentCount=1;
        sub.pColorAttachments=&ref;

        VkSubpassDependency dep{};
        dep.srcSubpass=0;
        dep.dstSubpass=VK_SUBPASS_EXTERNAL;
        dep.srcStageMask=
            VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
        dep.dstStageMask=
            VK_PIPELINE_STAGE_TRANSFER_BIT;
        dep.srcAccessMask=
            VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
        dep.dstAccessMask=
            VK_ACCESS_TRANSFER_READ_BIT;

        VkRenderPassCreateInfo ri{};
        ri.sType=VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
        ri.attachmentCount=1;
        ri.pAttachments=&attachment;
        ri.subpassCount=1;
        ri.pSubpasses=&sub;
        ri.dependencyCount=1;
        ri.pDependencies=&dep;

        if(vkCreateRenderPass(
            device,&ri,nullptr,&t.pass)!=VK_SUCCESS)
            return false;

        VkFramebufferCreateInfo fi{};
        fi.sType=VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
        fi.renderPass=t.pass;
        fi.attachmentCount=1;
        fi.pAttachments=&t.view;
        fi.width=width;
        fi.height=height;
        fi.layers=1;

        return vkCreateFramebuffer(
            device,&fi,nullptr,&t.framebuffer)==VK_SUCCESS;
    }


    bool createDrawPipeline(
        RenderTarget& t,
        uint32_t width,
        uint32_t height,
        std::span<const uint32_t> fragmentWords) {

        if(!t.pass || !t.framebuffer ||
           !width || !height)
            return false;

        if(!createShader(guestVertexSpv,t.vertex) ||
           !createShader(fragmentWords,t.fragment))
            return false;

        VkPipelineLayoutCreateInfo li{};
        li.sType=
            VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;

        if(vkCreatePipelineLayout(
            device,&li,nullptr,&t.layout)!=VK_SUCCESS)
            return false;

        VkPipelineShaderStageCreateInfo stages[2]{};

        for(auto& stage:stages){
            stage.sType=
                VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
            stage.pName="main";
        }

        stages[0].stage=VK_SHADER_STAGE_VERTEX_BIT;
        stages[0].module=t.vertex;
        stages[1].stage=VK_SHADER_STAGE_FRAGMENT_BIT;
        stages[1].module=t.fragment;

        VkVertexInputBindingDescription binding{};
        binding.binding=0;
        binding.stride=8;
        binding.inputRate=VK_VERTEX_INPUT_RATE_VERTEX;

        VkVertexInputAttributeDescription attribute{};
        attribute.location=0;
        attribute.binding=0;
        attribute.format=VK_FORMAT_R32G32_SFLOAT;
        attribute.offset=0;

        VkPipelineVertexInputStateCreateInfo vs{};
        vs.sType=
            VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;
        vs.vertexBindingDescriptionCount=1;
        vs.pVertexBindingDescriptions=&binding;
        vs.vertexAttributeDescriptionCount=1;
        vs.pVertexAttributeDescriptions=&attribute;

        VkPipelineInputAssemblyStateCreateInfo ia{};
        ia.sType=
            VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;
        ia.topology=VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;

        VkViewport viewport{
            0,0,float(width),float(height),0,1
        };

        VkRect2D scissor{{0,0},{width,height}};

        VkPipelineViewportStateCreateInfo vp{};
        vp.sType=
            VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;
        vp.viewportCount=1;
        vp.pViewports=&viewport;
        vp.scissorCount=1;
        vp.pScissors=&scissor;

        VkPipelineRasterizationStateCreateInfo rs{};
        rs.sType=
            VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;
        rs.polygonMode=VK_POLYGON_MODE_FILL;
        rs.cullMode=VK_CULL_MODE_NONE;
        rs.frontFace=VK_FRONT_FACE_COUNTER_CLOCKWISE;
        rs.lineWidth=1.0f;

        VkPipelineMultisampleStateCreateInfo ms{};
        ms.sType=
            VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;
        ms.rasterizationSamples=VK_SAMPLE_COUNT_1_BIT;

        VkPipelineColorBlendAttachmentState blend{};
        blend.colorWriteMask=15;

        VkPipelineColorBlendStateCreateInfo cb{};
        cb.sType=
            VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;
        cb.attachmentCount=1;
        cb.pAttachments=&blend;

        VkGraphicsPipelineCreateInfo pi{};
        pi.sType=
            VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;
        pi.stageCount=2;
        pi.pStages=stages;
        pi.pVertexInputState=&vs;
        pi.pInputAssemblyState=&ia;
        pi.pViewportState=&vp;
        pi.pRasterizationState=&rs;
        pi.pMultisampleState=&ms;
        pi.pColorBlendState=&cb;
        pi.layout=t.layout;
        pi.renderPass=t.pass;

        return vkCreateGraphicsPipelines(
            device,VK_NULL_HANDLE,1,
            &pi,nullptr,&t.pipeline)==VK_SUCCESS;
    }

    VkInstance instance{};
    VkPhysicalDevice physical{};
    VkDevice device{};
    VkQueue queue{};
    VkCommandPool pool{};
    VkCommandBuffer cmd{};
    VkFence fence{};

    VkPhysicalDeviceMemoryProperties memoryTypes{};
    std::map<Handle,Buffer> buffers;

    Handle nextHandle=1;
    uint64_t allocated=0;
    uint64_t completed=0;
    bool ready=false;

    void release(Buffer& b){
        if(b.mapped)
            vkUnmapMemory(device,b.memory);
        if(b.buffer)
            vkDestroyBuffer(device,b.buffer,nullptr);
        if(b.memory)
            vkFreeMemory(device,b.memory,nullptr);
        b={};
    }

    bool range(Handle h,uint64_t off,
               uint64_t size) const {
        auto it=buffers.find(h);
        return it!=buffers.end()
            && off<=it->second.size
            && size<=it->second.size-off;
    }

public:
    std::string gpuName;

    ScarlettVulkan()=default;
    ScarlettVulkan(const ScarlettVulkan&)=delete;
    ScarlettVulkan& operator=(
        const ScarlettVulkan&)=delete;

    ~ScarlettVulkan(){
        if(device){
            vkDeviceWaitIdle(device);
            for(auto& entry:buffers)
                release(entry.second);

            if(fence)
                vkDestroyFence(device,fence,nullptr);
            if(pool)
                vkDestroyCommandPool(device,pool,nullptr);

            vkDestroyDevice(device,nullptr);
        }

        if(instance)
            vkDestroyInstance(instance,nullptr);
    }

    bool initialize(){
        if(instance)return ready;

        VkApplicationInfo app{};
        app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
        app.pApplicationName="ALIEN XBOX V80";
        app.apiVersion=VK_API_VERSION_1_1;

        VkInstanceCreateInfo info{};
        info.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
        info.pApplicationInfo=&app;

        if(vkCreateInstance(&info,nullptr,&instance)
            !=VK_SUCCESS)return false;

        uint32_t count=0;
        if(vkEnumeratePhysicalDevices(
            instance,&count,nullptr)!=VK_SUCCESS
            || !count)return false;

        std::vector<VkPhysicalDevice> devices(count);

        if(vkEnumeratePhysicalDevices(
            instance,&count,devices.data())
            !=VK_SUCCESS)return false;

        for(auto gpu:devices){
            VkPhysicalDeviceProperties props{};
            vkGetPhysicalDeviceProperties(gpu,&props);

            if(props.vendorID==0x5143){
                physical=gpu;
                gpuName=props.deviceName;
                break;
            }
        }

#if defined(ALIEN_TEST_SOFTWARE_VULKAN)
        if(!physical){
            for(auto gpu:devices){
                VkPhysicalDeviceProperties props{};
                vkGetPhysicalDeviceProperties(gpu,&props);
                if(props.deviceType!=VK_PHYSICAL_DEVICE_TYPE_CPU)continue;
                physical=gpu;
                gpuName=props.deviceName;
                break;
            }
        }
#endif
        if(!physical)return false;

        uint32_t families=0;
        vkGetPhysicalDeviceQueueFamilyProperties(
            physical,&families,nullptr);

        std::vector<VkQueueFamilyProperties> props(families);

        vkGetPhysicalDeviceQueueFamilyProperties(
            physical,&families,props.data());

        uint32_t family=0;

        while(family<families &&
              (!props[family].queueCount ||
              !(props[family].queueFlags&
                VK_QUEUE_GRAPHICS_BIT)))
            ++family;

        if(family==families)return false;

        float priority=1.0f;

        VkDeviceQueueCreateInfo qi{};
        qi.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
        qi.queueFamilyIndex=family;
        qi.queueCount=1;
        qi.pQueuePriorities=&priority;

        VkDeviceCreateInfo di{};
        di.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
        di.queueCreateInfoCount=1;
        di.pQueueCreateInfos=&qi;

        if(vkCreateDevice(physical,&di,nullptr,&device)
            !=VK_SUCCESS)return false;

        vkGetDeviceQueue(device,family,0,&queue);

        vkGetPhysicalDeviceMemoryProperties(
            physical,&memoryTypes);

        VkCommandPoolCreateInfo pi{};
        pi.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
        pi.flags=VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
        pi.queueFamilyIndex=family;

        if(vkCreateCommandPool(device,&pi,nullptr,&pool)
            !=VK_SUCCESS)return false;

        VkCommandBufferAllocateInfo ai{};
        ai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        ai.commandPool=pool;
        ai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        ai.commandBufferCount=1;

        if(vkAllocateCommandBuffers(device,&ai,&cmd)
            !=VK_SUCCESS)return false;

        VkFenceCreateInfo fi{};
        fi.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;

        ready=vkCreateFence(device,&fi,nullptr,&fence)
            ==VK_SUCCESS;

        return ready;
    }

    bool createBuffer(uint64_t size,Handle& handle){
        handle=0;

        if(!ready || !size ||
           size>ScarlettGpu::MaxBuffer ||
           size>ScarlettGpu::MaxMemory-allocated ||
           buffers.size()>=4096 ||
           nextHandle==UINT64_MAX)
            return false;

        Buffer b{};
        b.size=size;

        VkBufferCreateInfo bi{};
        bi.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        bi.size=size;
        bi.usage=VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
                 VK_BUFFER_USAGE_TRANSFER_DST_BIT |
                 VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
                 VK_BUFFER_USAGE_VERTEX_BUFFER_BIT |
                 VK_BUFFER_USAGE_INDEX_BUFFER_BIT;
        bi.sharingMode=VK_SHARING_MODE_EXCLUSIVE;

        if(vkCreateBuffer(device,&bi,nullptr,&b.buffer)
            !=VK_SUCCESS)return false;

        VkMemoryRequirements req{};
        vkGetBufferMemoryRequirements(device,b.buffer,&req);

        b.allocationSize=req.size;
        if(req.size>ScarlettGpu::MaxMemory-allocated){
            release(b);
            return false;
        }
        constexpr auto required=
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
            VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;

        uint32_t type=0;

        while(type<memoryTypes.memoryTypeCount){
            if((req.memoryTypeBits&(1u<<type)) &&
               (memoryTypes.memoryTypes[type].propertyFlags
                &required)==required)
                break;

            ++type;
        }

        if(type==memoryTypes.memoryTypeCount){
            release(b);
            return false;
        }

        VkMemoryAllocateInfo mi{};
        mi.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        mi.allocationSize=req.size;
        mi.memoryTypeIndex=type;

        if(vkAllocateMemory(device,&mi,nullptr,&b.memory)
            !=VK_SUCCESS ||
           vkBindBufferMemory(device,b.buffer,b.memory,0)
            !=VK_SUCCESS ||
           vkMapMemory(device,b.memory,0,VK_WHOLE_SIZE,
                       0,&b.mapped)!=VK_SUCCESS){
            release(b);
            return false;
        }

        std::memset(b.mapped,0,size);

        try {
            buffers.emplace(nextHandle,b);
        } catch(const std::bad_alloc&){
            release(b);
            return false;
        }

        handle=nextHandle++;
        allocated+=b.allocationSize;

        return true;
    }

    bool destroyBuffer(Handle h){
        if(!ready)return false;

        auto it=buffers.find(h);
        if(it==buffers.end())return false;

        allocated-=it->second.allocationSize;
        release(it->second);
        buffers.erase(it);

        return true;
    }

    bool upload(Handle h,uint64_t off,
                std::span<const uint8_t> data){
        if(!ready || !range(h,off,data.size()))
            return false;

        if(!data.empty())
            std::memcpy(
                static_cast<uint8_t*>(buffers.at(h).mapped)+off,
                data.data(),data.size());

        return true;
    }

    bool download(Handle h,uint64_t off,
                  std::span<uint8_t> data) const {
        if(!ready || !range(h,off,data.size()))
            return false;

        if(!data.empty())
            std::memcpy(data.data(),
                static_cast<const uint8_t*>(
                    buffers.at(h).mapped)+off,
                data.size());

        return true;
    }

    bool execute(std::span<const Command> commands){
        if(!ready || commands.size()>65536 ||
           completed==UINT64_MAX)
            return false;

        // Validate the complete batch before submission.
        for(const auto& c:commands){
            if(!c.size ||
               !range(c.dst,c.dstOffset,c.size))
                return false;

            if(c.op==Opcode::fill){
                if((c.dstOffset|c.size)&3)
                    return false;
            }else if(c.op==Opcode::copy){
                if(!range(c.src,c.srcOffset,c.size))
                    return false;

                if(c.src==c.dst &&
                   c.srcOffset<c.dstOffset+c.size &&
                   c.dstOffset<c.srcOffset+c.size)
                    return false;
            }else return false;
        }

        if(vkResetCommandBuffer(cmd,0)!=VK_SUCCESS)
            return false;

        VkCommandBufferBeginInfo begin{};
        begin.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        begin.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

        if(vkBeginCommandBuffer(cmd,&begin)!=VK_SUCCESS)
            return false;

        for(const auto& c:commands){
            if(c.op==Opcode::fill){
                vkCmdFillBuffer(
                    cmd,buffers.at(c.dst).buffer,
                    c.dstOffset,c.size,c.pattern);
            }else{
                VkBufferCopy copy{};
                copy.srcOffset=c.srcOffset;
                copy.dstOffset=c.dstOffset;
                copy.size=c.size;

                vkCmdCopyBuffer(
                    cmd,buffers.at(c.src).buffer,
                    buffers.at(c.dst).buffer,1,&copy);
            }

            VkMemoryBarrier barrier{};
            barrier.sType=VK_STRUCTURE_TYPE_MEMORY_BARRIER;
            barrier.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
            barrier.dstAccessMask=
                VK_ACCESS_TRANSFER_READ_BIT |
                VK_ACCESS_TRANSFER_WRITE_BIT;

            vkCmdPipelineBarrier(
                cmd,VK_PIPELINE_STAGE_TRANSFER_BIT,
                VK_PIPELINE_STAGE_TRANSFER_BIT,
                0,1,&barrier,0,nullptr,0,nullptr);
        }

        VkMemoryBarrier host{};
        host.sType=VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        host.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
        host.dstAccessMask=VK_ACCESS_HOST_READ_BIT;

        vkCmdPipelineBarrier(
            cmd,VK_PIPELINE_STAGE_TRANSFER_BIT,
            VK_PIPELINE_STAGE_HOST_BIT,
            0,1,&host,0,nullptr,0,nullptr);

        if(vkEndCommandBuffer(cmd)!=VK_SUCCESS)
            return false;

        if(vkResetFences(device,1,&fence)!=VK_SUCCESS)
            return false;

        VkSubmitInfo submit{};
        submit.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submit.commandBufferCount=1;
        submit.pCommandBuffers=&cmd;

        if(vkQueueSubmit(queue,1,&submit,fence)
            !=VK_SUCCESS){
            ready=false;
            return false;
        }

        if(vkWaitForFences(
            device,1,&fence,VK_TRUE,UINT64_MAX)
            !=VK_SUCCESS){
            ready=false;
            return false;
        }

        ++completed;
        return true;
    }


    bool drawTriangles(
        Handle vertices,
        uint64_t vertexOffset,
        uint32_t vertexCount,
        Handle output,
        uint64_t outputOffset,
        uint32_t width,
        uint32_t height,
        std::span<const uint32_t> fragmentWords) {

        if(!ready || completed==UINT64_MAX ||
           !width || !height ||
           width>2048 || height>2048 ||
           !vertexCount || vertexCount>1048576 ||
           vertexCount%3 ||
           vertexOffset%4 || outputOffset%16 ||
           vertices==output)
            return false;

        const uint64_t bytes=
            uint64_t(width)*height*16;

        if(!range(vertices,vertexOffset,
                  uint64_t(vertexCount)*8) ||
           !range(output,outputOffset,bytes))
            return false;

        RenderTarget t(device);

        if(!createRenderTarget(t,width,height) ||
           !createDrawPipeline(
               t,width,height,fragmentWords))
            return false;

        if(vkResetCommandBuffer(cmd,0)!=VK_SUCCESS)
            return false;

        VkCommandBufferBeginInfo begin{};
        begin.sType=
            VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        begin.flags=
            VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

        if(vkBeginCommandBuffer(cmd,&begin)!=VK_SUCCESS)
            return false;

        VkMemoryBarrier input{};
        input.sType=VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        input.srcAccessMask=
            VK_ACCESS_HOST_WRITE_BIT |
            VK_ACCESS_TRANSFER_WRITE_BIT;
        input.dstAccessMask=
            VK_ACCESS_VERTEX_ATTRIBUTE_READ_BIT;

        vkCmdPipelineBarrier(
            cmd,
            VK_PIPELINE_STAGE_HOST_BIT |
            VK_PIPELINE_STAGE_TRANSFER_BIT,
            VK_PIPELINE_STAGE_VERTEX_INPUT_BIT,
            0,1,&input,0,nullptr,0,nullptr);

        VkClearValue clear{};
        clear.color.float32[3]=1.0f;

        VkRenderPassBeginInfo rb{};
        rb.sType=
            VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
        rb.renderPass=t.pass;
        rb.framebuffer=t.framebuffer;
        rb.renderArea={{0,0},{width,height}};
        rb.clearValueCount=1;
        rb.pClearValues=&clear;

        vkCmdBeginRenderPass(
            cmd,&rb,VK_SUBPASS_CONTENTS_INLINE);

        vkCmdBindPipeline(
            cmd,VK_PIPELINE_BIND_POINT_GRAPHICS,
            t.pipeline);

        VkBuffer vertexBuffer=
            buffers.at(vertices).buffer;

        VkDeviceSize offset=vertexOffset;

        vkCmdBindVertexBuffers(
            cmd,0,1,&vertexBuffer,&offset);

        vkCmdDraw(cmd,vertexCount,1,0,0);

        vkCmdEndRenderPass(cmd);

        VkBufferImageCopy copy{};
        copy.bufferOffset=outputOffset;
        copy.imageSubresource={
            VK_IMAGE_ASPECT_COLOR_BIT,0,0,1
        };
        copy.imageExtent={width,height,1};

        vkCmdCopyImageToBuffer(
            cmd,t.image,
            VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
            buffers.at(output).buffer,1,&copy);

        VkMemoryBarrier host{};
        host.sType=VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        host.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
        host.dstAccessMask=VK_ACCESS_HOST_READ_BIT;

        vkCmdPipelineBarrier(
            cmd,VK_PIPELINE_STAGE_TRANSFER_BIT,
            VK_PIPELINE_STAGE_HOST_BIT,
            0,1,&host,0,nullptr,0,nullptr);

        if(vkEndCommandBuffer(cmd)!=VK_SUCCESS ||
           vkResetFences(device,1,&fence)!=VK_SUCCESS)
            return false;

        VkSubmitInfo submit{};
        submit.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submit.commandBufferCount=1;
        submit.pCommandBuffers=&cmd;

        if(vkQueueSubmit(queue,1,&submit,fence)
           !=VK_SUCCESS){
            ready=false;
            return false;
        }

        if(vkWaitForFences(
            device,1,&fence,VK_TRUE,UINT64_MAX)
            !=VK_SUCCESS){
            ready=false;
            vkDeviceWaitIdle(device);
            return false;
        }

        ++completed;
        return true;
    }

    bool drawDxbcTriangles(
        Handle vertices,
        uint64_t vertexOffset,
        uint32_t vertexCount,
        Handle output,
        uint64_t outputOffset,
        uint32_t width,
        uint32_t height,
        std::span<const uint8_t> dxbc) {

        if(dxbc.empty() || dxbc.size()>1048576)
            return false;

        auto words=translateDxbcPixel(dxbc);

        if(words.empty())
            return false;

        return drawTriangles(
            vertices,vertexOffset,vertexCount,
            output,outputOffset,width,height,words);
    }

    uint64_t completedFence() const {
        return completed;
    }

    uint64_t allocatedBytes() const {
        return allocated;
    }

    size_t resourceCount() const {
        return buffers.size();
    }
};

}
