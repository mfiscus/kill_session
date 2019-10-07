#!/usr/bin/env bash

# This tool was written to [ex]terminate abandoned docker services


# strict mode
set -Eeuo pipefail
IFS=$'\n\t'

# debug mode
#set -o verbose

# define global variables

# script name
readonly script_name=$( echo ${0##*/} | sed 's/\.sh*$//' )

# tool name
readonly tool_name="Kill Session"

# get logname
readonly logname=$( whoami )

# brand name
readonly brand_name="Fiscus"

# columns array
readonly columns=( "ID" "NAME" "STATUS" )


# cleanup working copy
function __cleanup() {
    dialog --clear
    clear

    return

}


# remove temporary files upon trapping SIGHUP/SIGINT/SIGKILL/SIGTERM/SIGEXIT
trap __cleanup HUP INT KILL TERM


# function to catch error messages
# ${1} = error message
# ${2} = exit code
function __throw_error() {

    # validate arguments
    if [ ${#} -eq 2 ]; then
        local message=${1}
        local exit_code=${2}

        # log specific error message to syslog and write to STDERR
        logger -s -p user.err -t ${script_name}"["${logname}"]" -- ${message}

        exit ${exit_code}

    else

        # log generic error message to syslog and write to STDERR
        logger -s -p user.err -t ${tool_name}"["${logname}"]" -- "an unknown error occured"

        exit 255

    fi

}


# interpret command-line arguments

# usage
function __print_usage() {
    # disable verbosity to enhance readablity
    set +o verbose

    # print usage
    echo -e "\n\nUsage options:"
    echo -e "\t-h | --help"
    echo -e "\t-i | --container-id <container id>"
    echo -e "\t-q | --quiet"
    echo -e "\t-v | --verbose"
    echo -e "\nExample usage:"
    echo -e "\t"${script_name}" --quiet --container-id <container ID>"
    echo -e "\t"${script_name}" --help\n"
    
    return

}


function __get_container_id() {
    local -A container
    local -a container_id container_name container_status choice
    local container_count=0
    local choice_count=0
    local options eachline onevalue c

    options="
        dialog 
            --shadow 
            --cancel-label \"Quit\" 
            --backtitle \"${tool_name}\" 
            --menu \"Select container to terminate:\" 0 0 0" 



    for eachline in $(docker ps --filter status=running --format "{{.ID}}|{{.Names}}|{{.Status}}" | grep -v ecs | awk -F '|' '{print "declare -A container=(['''${columns[0]}''']=\""$1"\" ['''${columns[1]}''']=\""$2"\" ['''${columns[2]}''']=\""$3"\" )" }'); do
        for onevalue in ${eachline}; do
            # build ${container[@]} associative array
            eval "${onevalue}"

            # display array declaration for debugging
            #declare -p container

            container_id[${container_count}]=${container[${columns[0]}]}
            container_name[${container_count}]=${container[${columns[1]}]}
            container_status[${container_count}]=${container[${columns[2]}]}

            options+="
                \""${container_id[${container_count}]}"\" \""${container_name[${container_count}]}"  "${container_status[${container_count}]}"\""

            (( ++container_count ))
        
        done

    done

    # strip any trailing slashes
    options=$( echo ${options} | sed 's:\\*$::' )

    for c in $( eval "${options}" 3>&2 2>&1 1>&3 ); do
        choice[${choice_count}]=${c}
        (( ++choice_count ))

    done

    # debug
    #declare -p choice

    echo ${choice[0]:-}

}


# terminate container
# ${1} = container id
function __terminate_container() {
    if [ ${#} -eq 1 ]; then
        local container_id=${1}

        docker kill -s KILL ${container_id} &>/dev/null

        return ${?}

    else
        return 255
    
    fi

}


# function to confirm selection
# $1 = container ID
function __confirm_action() {
    # validate argument
    if [ $# -eq 1 ]; then
        # declare variables local to this function
        local container_id=${1}
        local confirmation c choice_count=0
        local -a choice
        
        
        confirmation="
            dialog
                --shadow 
                --clear 
                --cancel-label \"Cancel\" 
                --backtitle \"${tool_name}\" 
                --inputbox \"Are you sure you want to terminate:\n\n"${container_id}"\n\nType CONFIRM: \" 0 0 "
        
        

        # launch dialog and split output into an array
        # strip any trailing slashes
        confirmation=$( echo ${confirmation} | sed 's:\\*$::' )

        for c in $( eval "${confirmation}" 3>&2 2>&1 1>&3 ); do
            choice[${choice_count}]=${c}
            (( ++choice_count ))

        done

        [ -z ${choice[0]:-} ] && choice[0]="cancel"

        # case return value (in lower case)
        case "${choice[0],,}" in
            "confirm") # positive confirmation
                # just in case the object has a null property
                if [ -n "${choice[0]:-}" ]; then
                    # return true
                    return 0
                    
                else
                    # this shouldn't happen unless the api is broken
                    __throw_error "unexpected response" 255
                    
                fi
                ;;
                
            *)  # negative confirmation
                __cleanup
                return 1
                ;;
                
        esac
        
    fi
    
}


# function to display wait message
# $1 = message
function __please_wait() {
    # validate argument
    if [ $# -eq 1 ]; then
        local wait_message=${1}
        dialog \
            --keep-window \
            --shadow \
            --backtitle "${tool_name}" \
            --infobox ${wait_message} 7 40

    fi
}


# function to display wait message
# $1 = message
function __done_prompt() {
    # validate argument
    if [ $# -eq 1 ]; then
        local wait_message=${1}
        dialog \
            --shadow \
            --backtitle "${tool_name}" \
            --msgbox ${wait_message} 7 40

    fi
}


# check for dependancies
# ${1} = dependancy
function __check_dependancy() {
    if [ ${#} -eq 1 ]; then
        local dependancy=${1}
        local exit_code=${null:-}

        type ${dependancy} &>/dev/null; exit_code=${?}
        
        if [ ${exit_code} -ne 0 ]; then
            return 255

        fi

    else
        return 1
        
    fi
    
}


####################
### main program ###
####################

# validate dependancies
readonly -a dependancies=( 'dialog' 'docker' 'logger' )
declare -i dependancy=0

while [ "${dependancy}" -lt "${#dependancies[@]}" ]; do
    __check_dependancy ${dependancies[${dependancy}]} || __throw_error ${dependancies[${dependancy}]}" required" ${?}

    (( ++dependancy ))

done

unset dependancy


# make sure we're using least bash 4 for proper support of associative arrays
[ $( echo ${BASH_VERSION} | grep -o '^[0-9]' ) -ge 4 ] || __throw_error "Please upgrade to at least bash version 4" ${?}


# Transform long options to short ones
for argv in "${@}"; do
    case "${argv}" in
        "--help"|"?")
            set -- "${@}" "-h"
            ;;

        "--container-id")
            set -- "${@}" "-i"
            ;;

        "--quiet")
            set -- "${@}" "-q"
            ;;

        "--verbose")
            set -- "${@}" "-v"
            ;;
        
        *)
            set -- "${@}" "${argv}"
            ;;

    esac

    shift

done


# Parse short options
declare -i OPTIND=1
declare optspec="hiqv"
while getopts "${optspec}" opt; do
    case $opt in
        "h")
            __print_usage
            exit 0
            ;;

        "i")
            declare container_id=${!OPTIND:-}
            (( ++OPTIND ))
            ;;

        "q")
            readonly quiet=1
            ;;

        "v")
            set -o verbose
            ;;

        *)
            __print_usage
            exit 1
            ;;

    esac

done


# verify docker is running on this system
[ $( docker ps &>/dev/null; echo ${?} ) -eq 0 ] || __throw_error "Docker is not running on this host" ${?}


# verify there is at least one container running on this system
[ $( docker ps --filter status=running --format "{{.ID}}" | grep -v ecs | wc -l ) -ge 1 ] || __throw_error "There are no containers running on this host" ${?}


# display loading dialog
[ -z ${quiet:-} ] && __please_wait "Loading "${brand_name}" containers"


# prompt user to select container if container-id wasn't specificed as parameter
if [ -z ${container_id:-} ]; then
    container_id=$( __get_container_id ) || __throw_error "Unable to get container names" 1

fi

if [ ! -z ${quiet:-} ]; then
    __terminate_container ${container_id} || __throw_error "Unable to terminate container" 1

else 
    __confirm_action ${container_id} && \
    __terminate_container ${container_id} && \
    __done_prompt "Successfully terminated "${container_id}

fi


# Cleaning up
__cleanup || __throw_error "Unable to clean up" 1