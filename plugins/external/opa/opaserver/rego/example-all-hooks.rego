
# Package for sample rego policies
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Shriti Priya
# This file is responsible for rego policies for each type of requests made, it could be prompt, resource or tool requests

package example



# Default policy values for all the policies
default allow_tool_pre_invoke := false
default allow_tool_post_invoke := false
default allow_prompt_pre_fetch := false
default allow_prompt_post_fetch := false
default allow_resource_pre_fetch := false
default allow_resource_post_fetch := false

password_pattern := `^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*\W)(?!.* ).{8,16}$`
curse_words := {"curseword1", "curseword2", "curseword3"}
disallowed_resources := {"root"}





allow_tool_pre_invoke if {
    contains(input.payload.args.repo_path, "IBM")
}

allow_prompt_pre_fetch if {
    some i
    word := curse_words[_]
    lower(input.text) == input_text
    contains(input_text, word)
    msg = sprintf("Input contains disallowed word: %s", [word])
}

allow_resource_pre_fetch if {
    some i
    word := disallowed_resources[_]
    lower(input.text) == input_text
    contains(input_text, word)
    msg = sprintf("Input contains disallowed resource: %s", [word])
    contains(input.payload.args.repo_path, "IBM")
}





allow_tool_post_invoke if {
    input.mode == "output"
    not contains_password
}

allow_prompt_post_fetch if {
    input.mode == "output"
    not contains_password
}

allow_resource_post_fetch if {
    input.mode == "output"
    not contains_password
}

# This rule checks if the input contains a value matching the pattern.
contains_password {
    some i
    value := input.payload[i]
    regex.match(password_pattern, value)
}








