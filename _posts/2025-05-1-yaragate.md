---
layout: post
title: Writing Yara rules with Lua plugins for Exoctl Engine
tags: [exoctl, plugin, linux, yara, malware analysis]
thumbnail: "assets/img/articles/yaragate/yara-plugin.png"
categories: article
---


In this article we are going to write a plugin for the _exoctl_ to make it even more powerful by using a plugin to assist with YARA rule manipulation.

Currently, the engine already has a default endpoint for performing _scans_ using YARA Rules and ClamAV, but it be extented further. In addition to initializing the rules that the engine already supports, we'll be able to create new rules and ensure that the engine automatically loads any new added rules. This way it just need to maintain a folder with rules and everytime a new one is added, the engine will automatically pull it in.

To make everything even more practical, web can allow the _upload_ of new rules via an endpoint using a this plugin, named **YaraGate**.

There are also some examples that can be checked at [developer-guide > plugins-lua > examples](https://maldecs-organization.gitbook.io/exoctl-docs/developer-guide/plugins-lua/examples)


## Content topics

* content
{:toc}

## Creating Configuration & Logging for the Plugin

It's possible to use engine's native _logging_ system, since it provides the `logging` property from the `_engine` object. However, there is an option to create a custom configuration including a specific log for it. This way, all the information is saved in a separate file, making organization easier.

Here is an example of a configuration file:

```toml
[plugin]
name = "YaraGate"
description = "Simple load Yara with folder to new rules"
author = "@remoob<https://github.com/rem0obb>"
version = 1

[logging]
name = "yaragate"
pattern = "[%Y-%m-%d %H:%M:%S] [%n] [%^%l%$] %v"
filepath = "logs/yaragate.log"
console.output_enabled = true
level = 1
trace_updates.interval = 0
type = "daily"
daily.max_size = 10485
daily.time = 14:30:00
daily.truncate = false
rotation.max_size = 10485
rotation.max_files = 100

[yaragate]
gateway.prefix = "/yaragate"
rules.path = "rules/"
rules.save_stream = "rules.yarc"
server.tick_time = 15 # 15 seconds

```

The _logging_ section follows a standard, and these _fields_ are necessary. If you want more details about each one, take a look at the engine's documentation at [user-guide > configuration > configuration-file > logging-section](https://github.com/exoctl/exoctl).

The objects that will be necessary will be created for the configuration and logging.

```lua
local config <const> = Configuration:new()
local logging <const> = Logging:new()
```

Set up the log and config and then load them.

```lua
config:setup("plugins/yaragate/yaragate.conf")
config:load()

logging:setup(config)
logging:load()
```

With this configuration, we can now access the information from the _config_ file and use the custom logs for my plugin, such as [`info`, `warn`, etc](https://github.com/exoctl/exoctl). This gives more control over the records, allowing to separate the plugin's logs from the main engine's logs.

## Creating a New Yara Instance

To create a Yara instance, just create the object and load the rules.

```lua
local yara <const> = Yara:new()
local rules_folder <const> = config:get("yaragate.rules.path")

-- Load Yara rules
local function load_rules()
    yara:load_rules(function()
        yara:load_rules_folder(rules_folder)
    end)
end
```

The rules from the folder specified in the _config_ will be compiled. After that, you can call `scan_bytes` or `scan_fast_bytes` methods.

## Creating a Tick for Rule Maintenance

The engine allows creating a type of _tick_, which is automatically called at defined intervals in milliseconds. We'll use this functionality to create a _tick_ that recompiles my rules every second, ensuring that any changes to the file are applied in real-time. The interval is fully configurable in the _config_ file.

```lua
-- Reload Yara rules and compiler
local function reload_yara()
    yara:unload_rules()
    yara:unload_compiler()
    yara:load_compiler()
end

local ftick <const> = function()
    logging:debug(("Maintaining rules, loading rules from folder '%s' ..."):format(rules_folder))

    reload_yara()
    load_rules()
    yara:load_rules_file(rules_save_stream)
end

-- Set up periodic tick
engine.server:tick(tick_time * 1000, ftick)
```

## Creating a Web Gateway Endpoint

Creating a _gateway_ to perform _scans_ with the loaded rules is quite simple. Just use `_engine.server` directly, which already automatically sets up an _endpoint_. There's also the option to run a server exclusively for the plugin, but since this is something simpler, there's no need to go down that path.

```lua
local function log_request(req) -- function that will be responsible for always logging request information such as IP, URL, etc.
    logging:info(("Request received: method=%s, url=%s, remote_ip=%s, http_version=%d.%d, keep_alive=%s")
        :format(req.method, req.url, req.remote_ip_address, req.http_ver_major, req.http_ver_minor,
            tostring(req.keep_alive))
    )
end

local function create_route(endpoint, method, handler) -- Generic function that will be responsible for creating the gateways/endpoints of our plugin
    Web.new(_engine.server, gateway_prefix .. endpoint, function(req)
        log_request(req)
        return handler(req)
    end, method)
end
```

We created some helper functions to make it easier to create the _gateways_, and now we're ready to define our routes.

## Creating the `/get/rules` Endpoint

To check which rules the plugin has loaded, let's create an _endpoint_ supporting GET requests that returns all the currently active rules. This way, we can easily see which rules were successfully loaded and are in use.

```lua
create_route("/get/rules", HTTPMethod.Get, function(req)
    local rules_json = Json:new()

    yara:rules_foreach(function(rules)
        local meta = Json:new()

        yara:metas_foreach(rules, function(metas)
            local value = (metas.type ~= 2) and metas.integer or metas.string
            meta:add(metas.identifier, value)
        end)

        local rule = Json:new()
        rule:add("identifier", rules.identifier)
        rule:add("namespace", rules.ns.name)
        rule:add("num_atoms", rules.num_atoms)
        rule:add("meta", meta)

        rules_json:add(rules.identifier, rule)
    end)

    local json_response = Json:new()
    json_response:add("rules", rules_json)

    return Response.new(200, "application/json", json_response:to_string())
end)
```

Here we return a raw _JSON_, which will be useful later, and also some YARA functions, such as `metas_foreach`. This function allows extracting information about the rules loaded by the `Yara` instance.

As mentioned before, you can check the examples section at [developer-guide > plugins-lua > examples#get-all-rules](https://github.com/exoctl/exoctla). There, you'll find a practical example of how to use `metas_foreach` to get information about the loaded rules.

## Creating the `/scan` Endpoint

Since the instance is already initialized we can access the compiled rules we can setup a `scan` _endpoint_ to make the process more complete using `scan_bytes`.

```lua
create_route("/scan", HTTPMethod.Post, function(req)
    local rules_match = Json:new()

    yara:scan_bytes(req.body, function(message, rules)
        if message == flags_yara.CALLBACK_MSG_RULE_MATCHING then
            local rule = Json:new()
            rule:add("identifier", rules.identifier)
            rule:add("namespace", rules.ns.name)
            rule:add("num_atoms", rules.num_atoms)
            rules_match:add(rules.identifier, rule)

            return flags_yara.CALLBACK_CONTINUE
        elseif message == flags_yara.CALLBACK_MSG_SCAN_FINISHED then
            logging:info(("Scan completed successfully for IP %s"):format(req.remote_ip_address))
        end

        return flags_yara.CALLBACK_CONTINUE
    end, flags_yara.SCAN_FLAGS_FAST_MODE)

    local json_response = Json:new()
    json_response:add("sha256", _data.metadata.sha:gen_sha256_hash(req.body))
    json_response:add("rules_match", rules_match)

    return Response.new(200, "application/json", json_response:to_string())
end)
```

Since YARA supports various _scan_ options, such as `SCAN_FLAGS_FAST_MODE`, `SCAN_FLAGS_NO_TRYCATCH`, `SCAN_FLAGS_REPORT_RULES_MATCHING`, `SCAN_FLAGS_REPORT_RULES_NOT_MATCHING`, among others, it's convenient to create a table to store them. This table will function as an _enum_, making it easier to configure the _flags_ when using `scan_bytes`.

```lua
local flags_yara <const> = {
    CALLBACK_MSG_RULE_MATCHING = 1,
    CALLBACK_CONTINUE = 0,
    SCAN_FLAGS_FAST_MODE = 1,
    CALLBACK_MSG_SCAN_FINISHED = 3
}
```

The file comes in the _body_ of the request, so it's a good idea to return the SHA-256 of that _body_ so that the user can map which file was scanned. For this, we used the object that the engine already provides: `_data.metadata.sha:gen_sha256_hash(req.body)`.

## Creating the `/force/tick/yara` Endpoint

This _endpoint_ basically forces the execution of the server's _tick_ this way when called, it directly triggers the function managed by the server, ensuring that the rules are recompiled immediately.

```lua
create_route("/force/tick/yara", HTTPMethod.Post, function(req)
    ftick()
end)
```

## Creating the `/load/yara/rule` Endpoint

With this _endpoint_, you can load new YARA rules without losing the ones that have already been compiled from the file. Additionally, if any rule is not compiled correctly, the system maintains the last valid version of the rules, using the server's last _backup_. This ensures that compilation failures do not affect the plugin's operation.

```lua
create_route("/load/yara/rule", HTTPMethod.Post, function(req)
    local json = Json:new()
    json:from_string(req.body)

    local rule = json:get("rule")
    local namespace = json:get("namespace")

    if not rule or not namespace then
        local message = Json:new()
        message:add("message", "Missing required fields: 'rule' and 'namespace' are required.")

        return Response.new(400, "application/json", message:to_string())
    end

    -- Reload Yara with new rule
    reload_yara()
    local compiled_rule = true

    yara:load_rules(function()
        if (yara:set_rule_buff(rule, namespace) ~= 0) then
            reload_yara()
            compiled_rule = false
        end

        load_rules()
    end)

    if compiled_rule then
        yara:save_rules_file(rules_save_stream) -- Backup rules
        local message = Json:new()
        message:add("message", "Rule compiled successfully")

        return Response.new(200, "application/json", message:to_string())
    end

    local message = Json:new()
    message:add("message", "The rule was not compiled successfully, check for possible syntax errors")

    return Response.new(400, "application/json", message:to_string())
end)
```

The _endpoint_ expects to receive a POST request with a _JSON_ containing the YARA rule and its respective _namespace_.

Example of expected _body_:

```json
{
  "rule": "rule Malware { condition: true }",
  "namespace": "test"
}
```

## Running the Plugin

Running the engine and loading the plugin:

![yara-gate]({{ "/assets/img/articles/yaragate/engine-loading-plugin.png" | relative_url }})

The _endpoints_ were loaded successfully. Now we can test them and verify the plugin's operation using [exoctl-cli](https://github.com/exoctl/exoctl-cli), an _open source_ tool from exoctl that facilitates communication with our engine/plugin.

### `/get/rules` Endpoint

Command:

```shell
$ lua5.4 src/exoctl-cli.lua -g plugins:plugin -e /yaragate/get/rules -m get
```

Response:

![yara-gate]({{ "/assets/img/articles/yaragate/get-rules.png" | relative_url }})

Our rules were compiled successfully, and we can now view them.

### `/scan` Endpoint

We can perform our scans with our compiled rules.

Command:

```shell
$ lua5.4 src/exoctl-cli.lua -g plugins:plugin -e /yaragate/scan --data /path/to/malware.elf -f  -m post --raw-data | jq
```

Response:

![yara-gate]({{ "/assets/img/articles/yaragate/scan.png" | relative_url }})

### `/load/yara/rule` Endpoint

Now, let's load a new rule into our endpoint and test both scenarios: one where the rule has issues and another where it is loaded successfully.

#### Successfully Loaded

Command:

```shell
$ lua5.4 src/exoctl-cli.lua -g plugins:plugin -e /yaragate/load/yara/rule -m post --data "{\"rule\": \"rule Malware { condition: true }\", \"namespace\": \"test\" }"
```

Response:

![yara-gate]({{ "/assets/img/articles/yaragate/rule-compiled.png" | relative_url }})

#### Error Loading

Command:

```shell
$ lua5.4 src/exoctl-cli.lua -g plugins:plugin -e /yaragate/load/yara/rule -m post --data "{\"rule\": \"Malware { condition: true }\", \"namespace\": \"test\" }" # removed 'rule'
```

Response:

![yara-gate]({{ "/assets/img/articles/yaragate/rule-error-compiled.png" | relative_url }})
