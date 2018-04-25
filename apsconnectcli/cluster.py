import base64
import os
import sys
from collections import namedtuple
from datetime import datetime, timedelta
from time import sleep

from apsconnectcli.action_logger import Logger

LOG_DIR = os.path.expanduser('~/.apsconnect')

MAX_RESTARTS = 5
NUM_RETRIES = 5

POLL_INTERVAL = 5
TIMEOUT = 5 * 60

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, "apsconnect.log")

sys.stdout = Logger(LOG_FILE, sys.stdout)
sys.stderr = Logger(LOG_FILE, sys.stderr)

AvailabilityCheckResult = namedtuple('AvailabilityCheckResult', 'available message')


def read_cluster_certificate(ca_cert):
    try:
        with open(ca_cert) as _file:
            ca_cert_data = base64.b64encode(_file.read().encode())
    except Exception as e:
        print("Unable to read ca_cert file, error: {}".format(e))
        sys.exit(1)
    else:
        return ca_cert_data


def poll_deployment(core_v1, ext_v1, namespace, name):
    max_time = datetime.now() + timedelta(seconds=TIMEOUT)

    while True:
        deployment = ext_v1.read_namespaced_deployment(namespace=namespace, name=name)
        available = bool(deployment.status.available_replicas)
        error_reasons = ['InvalidImageName', 'CrashLoopBackOff', 'ErrImagePull']
        correct_reasons = ['ContainerCreating']

        if available:
            return AvailabilityCheckResult(True, "Deployment has just become available")

        if not check_containers_exist(core_v1, namespace, name, NUM_RETRIES, POLL_INTERVAL):
            return AvailabilityCheckResult(False, "No containers available in the deployment. "
                                                  "Are there sufficient resources?")

        pod = core_v1.list_namespaced_pod(namespace=namespace,
                                          label_selector='name={}'.format(name)).items[0]

        state = pod.status.container_statuses[0].state
        restart_count = pod.status.container_statuses[0].restart_count
        ready_condition = [c for c in pod.status.conditions if c.type == 'Ready'][0]

        if (ready_condition.status == 'False' and
                ready_condition.reason == 'ContainersNotReady' and
                restart_count > MAX_RESTARTS):
            log = get_log(name, core_v1, namespace)
            err_msg = "Readiness check failed. Verify that health check URL responds with " \
                      "status code 200. Connector's standard output:\n{}".format(log)
            return AvailabilityCheckResult(False, err_msg)

        if state.waiting:
            if state.waiting.reason in error_reasons:
                error_message = error_report(name,
                                             core_v1,
                                             namespace,
                                             state.waiting.reason,
                                             state.waiting.message)
                return AvailabilityCheckResult(False, error_message)
            elif state.waiting.reason not in correct_reasons:
                err_msg = "Unexpected error: {} {}".format(state.waiting.reason,
                                                           state.waiting.message)
                return AvailabilityCheckResult(False, err_msg)

        sleep(POLL_INTERVAL)
        sys.stdout.write('.')
        sys.stdout.flush()
        if datetime.now() > max_time:
            timeout_str = "Timed out after waiting {} seconds for deployment " \
                          "to become available".format(TIMEOUT)
            return AvailabilityCheckResult(False, timeout_str)


def check_containers_exist(core_v1, namespace, name, num_retries=5, poll_interval=5):
    attempt_num = 0
    while True:
        pods = core_v1.list_namespaced_pod(namespace=namespace,
                                           label_selector='name={}'.format(name)).items
        if pods and pods[0].status.container_statuses:
            return True

        attempt_num += 1
        if attempt_num >= num_retries:
            break
        sleep(poll_interval)

    return False


def get_log(name, core_v1, namespace):
    pods = core_v1.list_namespaced_pod(namespace=namespace,
                                       label_selector='name={}'.format(name)).items
    log = core_v1.read_namespaced_pod_log(namespace=namespace, name=pods[0].metadata.name)
    return log


def error_report(name, api, namespace, reason, message):
    if reason == 'CrashLoopBackOff':
        log = get_log(name, api, namespace)
        return "Container failed to start. Logs:\n{}".format(log)
    return "Error code: {};\n\nMessage: {}".format(reason, message)
