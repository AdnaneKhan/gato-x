from collections import defaultdict

import yaml


def build_workflow_source_map(workflow_yaml_node: yaml.Node) -> dict:
    source_map = {"jobs": defaultdict(lambda: {"steps": {}, "line": None})}

    if not isinstance(workflow_yaml_node, yaml.MappingNode):
        return source_map

    jobs_node = next(
        (
            value
            for key, value in workflow_yaml_node.value
            if isinstance(key, yaml.ScalarNode)
            and key.value == "jobs"
            and isinstance(value, yaml.MappingNode)
        ),
        None,
    )

    if not jobs_node:
        return source_map

    valid_jobs = filter(
        lambda item: isinstance(item[0], yaml.ScalarNode)
        and isinstance(item[1], yaml.MappingNode),
        jobs_node.value,
    )

    for job_key, job_value in valid_jobs:
        job_name = job_key.value
        source_map["jobs"][job_name]["line"] = job_key.start_mark.line + 1

        steps_node = next(
            (
                job_val
                for job_k, job_val in job_value.value
                if isinstance(job_k, yaml.ScalarNode)
                and job_k.value == "steps"
                and isinstance(job_val, yaml.SequenceNode)
            ),
            None,
        )

        if steps_node:
            source_map["jobs"][job_name]["steps"] = {
                step_index: step_value.start_mark.line + 1
                for step_index, step_value in enumerate(steps_node.value)
            }

    return source_map


def build_composite_source_map(composite_yaml_node: yaml.Node) -> dict:
    source_map = {"steps": {}}

    if not isinstance(composite_yaml_node, yaml.MappingNode):
        return source_map

    runs_node = next(
        (
            value
            for key, value in composite_yaml_node.value
            if isinstance(key, yaml.ScalarNode)
            and key.value == "runs"
            and isinstance(value, yaml.MappingNode)
        ),
        None,
    )

    if not runs_node:
        return source_map

    steps_node = next(
        (
            value
            for key, value in runs_node.value
            if isinstance(key, yaml.ScalarNode)
            and key.value == "steps"
            and isinstance(value, yaml.SequenceNode)
        ),
        None,
    )

    if not steps_node:
        return source_map

    for step_index, step_value in enumerate(steps_node.value):
        source_map["steps"][step_index] = step_value.start_mark.line + 1

    return source_map
