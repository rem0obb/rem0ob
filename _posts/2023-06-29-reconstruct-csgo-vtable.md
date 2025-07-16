---
layout: post
title:  "Reconstructing the CS:GO VTable on Linux"
tags: [linux, reverse engineering, game hacking]
thumbnail: "assets/img/articles/csgo/banner-csgo.png"
categories: article
---

As many have noticed, my focus on this blog heavily involves Linux. However, I haven't found much content related to Linux and gaming. Whenever I have some free time, I enjoy playing a bit of CS:GO (Counter-Strike: Global Offensive) and decided to take a look at how the game works under the hood. This article aims to reconstruct the CS:GO VTable, or at least a small part of the CS:GO client VTable. To follow along with this article, I recommend having knowledge of the C++ language and some familiarity with using the IDA tool.

To proceed with the article, you will need to have CS:GO installed on your machine to analyze the binary alongside me. If you cannot install CS:GO on your machine, I will provide this [repository](https://github.com/VitorMob/GHInterfacesCSGO/tree/main/packages) with the shared libraries used by CS:GO that we will analyze in this article.

To reconstruct the CS:GO VTable, I will use the SDK provided by Valve itself. I will utilize the GitHub repository called "source-sdk-2013" available at [https://github.com/ValveSoftware/source-sdk-2013](https://github.com/ValveSoftware/source-sdk-2013).

## Content topics

* content
{:toc}

# Analyzing the csgo_linux64 Binary

Let’s start by analyzing the main CS:GO executable, located at `~/.steam/steam/steamapps/common/Counter-Strike Global Offensive/csgo_linux64`. We will use IDA for this analysis.

After loading our binary into IDA, I recommend adjusting the settings as follows:

1. Go to `Options -> General -> Disassembly`:

   - Check the `[x] Functions Offset` option.
   - Check the `[x] Auto Comments` option.
   - Set the number of opcode bytes (graphical) to `16`.

<div class="info">
  <strong>Note:</strong> These settings will help improve code analysis and provide useful information during the process.
</div>

Now, let’s begin analyzing the binary starting from `main`, our main function. We can notice that the code is relatively small, but it contains an exported function called `dlopen`, which is used to obtain a handle to a shared library, load it into memory, and use it. We can check which library it is passing as a parameter and which function it is using by employing `dlsym` to retrieve the symbol and then calling the function.

![csgo]({{ "/assets/img/articles/csgo/csgo_dlopen.png" | relative_url }})

It is passing the path `bin/linux64/launcher_client.so` as a parameter to `dlopen` and then making a call to the `LauncherMain` function. Essentially, this acts as a loader. By analyzing the code, we can identify this as a potential entry point.

Let’s create a shared library so we can load our own function instead of the original one, using the C++ language.

> compile: g++ -shared -fpic launcher_client.cpp -o launcher_client.so

launcher_client.cpp:
```c
#include <iostream>

extern "C"
{
    void LauncherMain(int argc, const char **argv)
    {
        std::cout << "[*] Loading LauncherClient.so" << std::endl;
    }
}
```

Great! Now that we have the library with the `LauncherMain` function, let’s move the generated library to `bin/linux64/launcher_client.so`. Then, we can run the game via the command line.

> execute: mv launcher_client.so bin/linux64/launcher_client.so

<div class="warning">
  <strong>Warning:</strong> I recommend backing up the original CS:GO library in a safe location before proceeding with replacing it with our custom library. This will ensure you have a backup copy in case you need to restore the original configuration later.
</div>

To run CS:GO via the command line, simply execute:

> execute: ~/.local/share/Steam/ubuntu12_32/steam-runtime/run.sh ~/.steam/steam/steamapps/common/Counter-Strike\ Global\ Offensive/csgo.sh

> output:

---

[*] Loading LauncherClient.so

---

Great, now that we’re inside the code, we have our entry point to proceed with the necessary changes or customizations. We can continue analyzing and modifying the code as needed.

Let’s start by making some changes to the code, loading the `LauncherMain` function from the original library.

> compile: g++ -shared -fpic launcher_client.cpp -o launcher_client.so -ldl

launcher_client.cpp:
```c
#include <dlfcn.h>
#include <iostream>

extern "C"
{
    void *dl = dlopen("<BACKUP_TO_LAUNCHER>", RTLD_NOW); // Opening the dynamic library and loading it using the second parameter `RTLD_NOW`
    if (dl)
    {
        void *LauncherMain = dlsym(dl, "LauncherMain"); // Obtaining the original symbol from LauncherClient
        if (LauncherMain)
        {
            LauncherMain_o = reinterpret_cast<void (*)(int argc, const char **argv)>(LauncherMain); // Performing a reinterpret_cast on the symbol to match the function signature
            LauncherMain_o(argc, argv); // Calling the original function
        }
        dlclose(dl); // Closing the library after the process is complete
    }
}
```

Don’t forget to provide the path to the backup of the original `launcher_client` library in `<BACKUP_TO_LAUNCHER>`.

> execute: ~/.local/share/Steam/ubuntu12_32/steam-runtime/run.sh ~/.steam/steam/steamapps/common/Counter-Strike\ Global\ Offensive/csgo.sh -steam

> output:

---

[*] Loading LauncherClient.so<br>
SDL video target is 'x11'<br>
This system supports the OpenGL extension GL_EXT_framebuffer_object.<br>
This system supports the OpenGL extension GL_EXT_framebuffer_blit.<br>
This system supports the OpenGL extension GL_EXT_framebuffer_multisample.<br>
This system DOES NOT support the OpenGL extension GL_APPLE_fence.<br>
This system DOES NOT support the OpenGL extension GL_NV_fence.<br>
This system supports the OpenGL extension GL_ARB_sync.<br>
This system supports the OpenGL extension GL_EXT_draw_buffers2.<br>
This system DOES NOT support the OpenGL extension GL_EXT_bindable_uniform.<br>
This system DOES NOT support the OpenGL extension GL_APPLE_flush_buffer_range.<br>
This system supports the OpenGL extension GL_ARB_map_buffer_range.<br>
This system supports the OpenGL extension GL_ARB_vertex_buffer_object.<br>
This system supports the OpenGL extension GL_ARB_occlusion_query.<br>
This system DOES NOT support the OpenGL extension GL_APPLE_texture_range.<br>
This system DOES NOT support the OpenGL extension GL_APPLE_client_storage.<br>
This system DOES NOT support the OpenGL extension GL_ARB_uniform_buffer.<br>
This system supports the OpenGL extension GL_ARB_vertex_array_bgra.<br>
This system supports the OpenGL extension GL_EXT_vertex_array_bgra.<br>

<...>

---

<div class="info">
  <strong>Note:</strong> When running CS:GO, it’s important to note that the "-steam" parameter is often used. This is due to a check performed by CS:GO in the `LauncherMain` function of the dynamic library `launcher_client.so`. If this parameter is not provided, CS:GO sets the "-insecure" flag by default.
</div>

After loading our binary into IDA, search for a text string.

1. Go to `Search -> Text...`.
   - Search for `-steam`.
   - Use the `F5` key to generate pseudocode to aid understanding.



![csgo]({{ "/assets/img/articles/csgo/insecure.png" | relative_url }})


# Analyzing the client_client Binary

Now, our dynamic library is loading the original library and invoking the genuine CS:GO `LauncherMain` function. Great! Now CS:GO is running. Let’s start analyzing the client, located at `~/.steam/steam/steamapps/common/Counter-Strike Global Offensive/csgo/bin/linux64/client_client.so`. Our goal is to reconstruct part of a class used by CS:GO. Load it into IDA, and let’s begin the analysis.

### ClientModeShared Class

Let’s restructure the `ClientModeShared` class, located in the "client" folder of the [SDK](https://github.com/ValveSoftware/source-sdk-2013/blob/master/mp/src/game/client/clientmode_shared.h). In the code, we can observe that the class has two interfaces/inheritances called `IClientMode` and `CGameEventListener`. These interfaces play an important role in the class’s functionality.

![csgo]({{ "/assets/img/articles/csgo/client_shared.png" | relative_url }})


Let’s analyze the string table generated by IDA to gain more insights into the code.

1. Go to `View -> Open subviews -> Strings`:
   - Use the key combination `CTRL+F` or go to the search option in the menu.
   - Search for `ClientModeShared` in the search box.

![csgo]({{ "/assets/img/articles/csgo/client_shared_strings.png" | relative_url }})

Great! We found a reference to the class in the `.rodata` section. This section typically contains read-only data that contributes to a non-writable segment in the process image. Now, let’s follow these steps to explore this reference in more detail:

1. Left-click on the reference found in the section.
2. In the dropdown menu, look for and select the option "List cross references to...".

![csgo]({{ "/assets/img/articles/csgo/list_cross.png" | relative_url }})

By following these steps, you can explore the cross-references to the class found in the `.rodata` section.

Great, we found the class! Now, to facilitate analysis and ensure better understanding in the future, let’s rename the offset referring to the class. To do this, follow these simple steps:

1. Left-click on the offset.
2. In the dropdown menu, click on the first option `rename`.
3. Rename it to `ClientModeShared`.

![csgo]({{ "/assets/img/articles/csgo/class_shared.png" | relative_url }})


Great, let’s start analyzing the functions related to the class to rename them according to the name found in the SDK. One of the functions we found is called `CreateMove` and belongs to the `IClientMode` class. Let’s check the source in the SDK [iclientmode](https://github.com/ValveSoftware/source-sdk-2013/blob/master/mp/src/game/client/iclientmode.h).

![csgo]({{ "/assets/img/articles/csgo/iclient.png" | relative_url }})


Let’s look for references within the `CreateMove` function to identify it in our virtual function table (vtable) found during the IDA analysis. One thing I often look for in an analysis is strings, as they greatly help in identifying functions. Let’s take a look at the implementation of the `CreateMove` function. We found it in the [clientmode_shared.cpp](https://github.com/ValveSoftware/source-sdk-2013/blob/master/mp/src/game/client/clientmode_shared.cpp) file.

![csgo]({{ "/assets/img/articles/csgo/create_move_shared.png" | relative_url }})

By analyzing the code, we can see that it performs a check to obtain the local player. If this check is successful, the `CreateMove` function is called from the object associated with the local player. It’s worth mentioning that this `CreateMove` function of the `pPlayer` object refers to the function in the `C_BasePlayer` class.

Notice that we don’t have strings referring to the function we want to find in IDA. However, below the `CreateMove` function, we found a function called `LevelInit`. Let’s take a look.

![csgo]({{ "/assets/img/articles/csgo/level_init.png" | relative_url }})

We can find the string `LevelInit` in our IDA’s `Strings` table, and `game_newmap` is the `mapname`.

![csgo]({{ "/assets/img/articles/csgo/levelInit_strings.png" | relative_url }})

So, let’s now explore the cross-references of this string.

![csgo]({{ "/assets/img/articles/csgo/levelinit_func.png" | relative_url }})


We landed directly on the `LevelInit` function. To confirm if this is indeed the function we’re looking for, we can examine other strings and even analyze the parameters identified by IDA.

A note: the function takes two parameters. The first refers to `this`, and the second refers to the `newmap` parameter. We can reconstruct the function by pressing the `F5` key and then renaming the parameters and the function name.

![csgo]({{ "/assets/img/articles/csgo/levelinit_recons.png" | relative_url }})

Now that we have a "better" version of our constructed function, by analyzing the SDK code, it’s clear that the `CreateMove` function is positioned above our `LevelInit` function. Therefore, logically, we can infer that the `CreateMove` function is located at this point.

![csgo]({{ "/assets/img/articles/csgo/found_CrateMove.png" | relative_url }})

Let’s analyze the function to confirm it is indeed the `CreateMove` function.

Indeed, there is a strong similarity between our `CreateMove` function and the function reconstructed by IDA. I’ve already updated the variable names and renamed the function to reflect these changes. Now everything is properly adjusted.

![csgo]({{ "/assets/img/articles/csgo/create_create_move.png" | relative_url }})

This way, we can fully reconstruct our `ClientModeShared` class vtable.

![csgo]({{ "/assets/img/articles/csgo/vtable.png" | relative_url }})

### CHLClient Class

Now, shall we hook the `CreateMove` function? We need to find an instance of the `IClientMode` class object to perform the hook and redirect execution to our custom function. To give you a complete understanding of what we’re going to do, I’ll provide a video tutorial from [`Guided Hacking`](https://guidedhacking.com/) that illustrates the process step by step. You’ll find the video at the end of the article to help you follow along and better understand the steps involved.

In the [`CHLClient`](https://github.com/ValveSoftware/source-sdk-2013/blob/0d8dceea4310fde5706b3ce1c70609d72a38efdf/mp/src/game/client/cdll_client_int.cpp#L598) class, we have a method called `HudProcessInput`, which is derived from the `IBaseClientDLL` interface.

![csgo]({{ "/assets/img/articles/csgo/chlclient.png" | relative_url }})

Using a more recent SDK I found on [GitLab](https://gitlab.com/KittenPopo/csgo-2018-source/-/tree/main), the `HudProcessInput` function has access to an instantiated pointer called `g_pClientMode`, but it can only be accessed by calling the `GetClientMode()` function. Let’s use the same strategy as before to reconstruct the vtable and determine precisely which index our function is located at in the class.

![csgo]({{ "/assets/img/articles/csgo/g_pClientMode.png" | relative_url }})


When we find our vtable, the image summarizes exactly what we did at the beginning of the article when analyzing the `ClientModeShared` vtable.

![csgo]({{ "/assets/img/articles/csgo/vtable_chlclient.png" | relative_url }})

Now we found the function we want to analyze, located above the `HudUpdate` method.

![csgo]({{ "/assets/img/articles/csgo/call_rax_return.png" | relative_url }})

We can observe that the `HudProcessInput` function is calling the mentioned method, `GetClientMode()`, and the return value is being stored in the `rax` register. Then, the value in memory pointed to by `rax` is being "dereferenced" and stored in the `rdx` register via the `mov rdx, [rax]` instruction. The vtable method is called at index `13`, but why `rdx+68h`? We are analyzing a 64-bit binary, and the indices of the pointer array in our vtable advance by 8 bytes. To determine the index value, simply calculate `0x68/8 = 13`, thus determining the index it is accessing in the vtable.

That said, in my [repository](), in the `Start` function, in summary, I obtain the pointer to the `CHLClient` class and then dereference this pointer to access our vtable. Next, I navigate to the offset of the `HudProcessInput` function, which is located at index `10`.

![csgo]({{ "/assets/img/articles/csgo/code.png" | relative_url }})

<blockquote>
  <p><strong style="color:#FF0C0C;">1:</strong> In summary, I’m obtaining the pointer to the interface that CS:GO creates using a macro <code>EXPOSE_SINGLE_INTERFACE_GLOBALVAR( CHLClient, IBaseClientDLL, "VClient018", gHLClient );</code>.</p>
  
  <p><strong style="color:#D7D7D7;">2:</strong> I’m using pointer arithmetic to access the vtable of our <code>VClient018</code> interface.</p>
  
  <p><strong style="color:#20FF0C;">3:</strong> Accessing index <code>10</code> in the vtable, which contains the pointer to the <code>HudProcessInput</code> function.</p>
  
  <p><strong style="color:#3300FF;">4:</strong> Adjusting the page permissions to allow writing, including the <code>HudProcessInput</code> function in the code.</p>
  
  <p><strong style="color:#FF0CF5;">5:</strong> Adding a function to handle the SIGTRAP interrupt.</p>
  
  <p><strong style="color:#FF0C0C;">6:</strong> Writing an interrupt at the end of the <code>HudProcessInput</code> function so our thread can obtain the value of <code>rax</code> through the CS:GO thread context.</p>
</blockquote>

#### Summary of How Interfaces Work

I’ll provide a summary of the code I wrote to obtain the pointer to the `CHLClient` class. In the CS:GO SDK, there’s a source file called [`interface.h`](https://github.com/ValveSoftware/source-sdk-2013/blob/master/mp/src/public/tier1/interface.h), which contains a class called `InterfaceReg`. This class includes a pointer to a method called `CreateInterfaceFn`, accessible by retrieving the `CreateInterface` symbol. Looking at the `CreateInterface` code, it calls another function called `CreateInterfaceInternal`. Let’s check what it does exactly:

![csgo]({{ "/assets/img/articles/csgo/interfaceh.png" | relative_url }})

Notice that it returns an `m_CreateFn` if the interface exists, meaning we have an object pointing to the interface passed as the `pName` parameter. How can we identify these interfaces? Simply check the macro called `EXPOSE_SINGLE_INTERFACE_GLOBALVAR`, which contains the class and the interface name that points to the class. This macro is responsible for establishing the relationship between the class and the interface, thus enabling access to and use of the functionalities provided by the interface. Example: `EXPOSE_SINGLE_INTERFACE_GLOBALVAR( CHLClient, IBaseClientDLL, "VClient018", gHLClient );`. In summary, my code is searching for these interfaces.

#### Summary of How Breakpoint Injection Works

I’ll explain how I obtained the value of `rax`, pointing to `IClientMode -> ClientModeShared`. My idea was to add a breakpoint using the `INT3` (`CC`) opcode, thus forcing a `SIGTRAP` and then handling it through my own thread initialized alongside CS:GO. Then, by capturing the entire context of the thread that triggered the `SIGTRAP`, I can obtain the value of `rax` and other registers, though that’s not our focus here.

The offset I chose to write our breakpoint in memory was precisely the last two bytes of the `HudProcessInput` method.

![csgo]({{ "/assets/img/articles/csgo/offset.png" | relative_url }})


The function responsible for collecting information from the thread that triggered the `SIGTRAP`.

![csgo]({{ "/assets/img/articles/csgo/vtable_code.png" | relative_url }})


We can observe the collection of the context of the thread that generated the `SIGTRAP` signal and then obtain the value of the `rax` register. This allows using pointer arithmetic to obtain the `ClientSharedMode` vtable. Next, it’s necessary to rewrite the original bytes that were overwritten to place the breakpoint.

# Hooking the CreateMove Function

Now that we have our `ClientSharedMode` vtable, let’s hook the `CreateMove` function.

![csgo]({{ "/assets/img/articles/csgo/hook_create_move.png" | relative_url }})

<blockquote>
  <p><strong style="color:#EEE400;">1:</strong> We have our signature generated by IDA to hook the function.</p>
  <p><strong style="color:#05FF00;">2:</strong> I’m storing the real offset of the CreateMove function in a function pointer, so we can call the real function within our hook function.</p>
  <p><strong style="color:#FF0C0C;">3:</strong> Our function responsible for the hook simply logs and then calls the real function.</p>
</blockquote>

# Running CS:GO

Let’s start running CS:GO to collect the information obtained during the static analysis and verify the effectiveness of our hook...

![csgo]({{ "/assets/img/articles/csgo/run_cs.png" | relative_url }})

![csgo]({{ "/assets/img/articles/csgo/hook_done.png" | relative_url }})


Excellent! Everything worked perfectly! I’ll make the code available in my repository [`GHInterfacesCSGO`](https://github.com/VitorMob/GHInterfacesCSGO).

# Conclusion

I plan to continue analyzing and improving the code from our analysis in this article. To follow these analyses, you can subscribe to receive notifications about new posts on the remoob blog.