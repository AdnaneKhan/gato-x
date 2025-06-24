from gatox.workflow_parser.expression_parser import ExpressionParser
from gatox.workflow_parser.expression_evaluator import ExpressionEvaluator


# steps.get_changes.outputs.changed != 0
# always() && (needs.build-artifacts.result == 'failure' || needs.github-release.result == 'failure')
# steps.get_changes.outputs.changed != 0
# steps.get_changes.outputs.changed != 0
# always() && (needs.backport.result == 'failure' || needs.backport-ent.result == 'failure')
# env.lychee_exit_code != 0
# ( github.event.action == 'opened' && steps.is-team-member.outputs.MESSAGE == 'false' )
# ${{ endsWith(inputs.repository-name, '-enterprise') }}
# ${{ endsWith(inputs.repository-name, '-enterprise') }}
# ${{ endsWith(inputs.repository-name, '-enterprise') }}
# ${{ endsWith(inputs.repository-name, '-enterprise') }}
# ${{ endsWith(inputs.repository-name, '-enterprise') }}
# ${{ endsWith(inputs.repository-name, '-enterprise') }}
# contains(inputs.sample-name, 'build')
# contains(inputs.sample-name, 'ent')
# always() && (needs.backport.result == 'failure' || needs.backport-ent.result == 'failure')
# steps.get_changes.outputs.changed != 0
# contains(steps.dependabot-metadata.outputs.dependency-names, 'github.com/hashicorp/terraform-plugin-sdk/v2' ) &&  (steps.dependabot-metadata.outputs.update-type == 'version-update:semver-patch' || steps.dependabot-metadata.outputs.update-type == 'version-update:semver-minor')
# always() && (needs.build-artifacts.result == 'failure' || needs.github-release.result == 'failure')
# always() && (needs.build-artifacts.result == 'failure' || needs.github-release.result == 'failure')
# github.event.deployment_status.state == 'success' && github.event.deployment.environment == 'production' && github.event.sender.id == 35613825
# github.event.deployment_status.state == 'success' && github.event.deployment.environment == 'preview' && github.event.sender.id == 35613825 && github.event.repository.name == 'dev-portal'
# always() && (needs.build-artifacts.result == 'failure' || needs.github-release.result == 'failure')
# always() && (needs.get-go-version.result == 'failure' || needs.acceptance-test.result == 'failure')
# always() && (needs.build-artifacts.result == 'failure' || needs.github-release.result == 'failure')
# ( github.event.action == 'opened' && steps.set-ticket-type.outputs.type != 'Task' ) || ( github.event.action == 'opened' && steps.set-ticket-type.outputs.type == 'Task' && steps.is-team-member.outputs.message == 'false' )
# ${{ github.ref != format('refs/tags/v{0}', steps.ext-version.outputs.content) }}
# ${{ github.ref != format('refs/tags/v{0}', steps.ext-version.outputs.VERSION) }}
# ( github.event.action == 'opened' && steps.is-team-member.outputs.MESSAGE == 'false' )
# contains(fromJSON('["success", "failure"]'), steps.test-version.outcome)
# contains(fromJSON('["success", "failure"]'), steps.test-version.outcome)
# always() && (needs.build-artifacts.result == 'failure' || needs.github-release.result == 'failure')
# steps.get_changes.outputs.changed != 0
# always() && (needs.tests-summarize.result == 'failure')
# ( github.event.action == 'opened' && steps.is-team-member.outputs.MESSAGE == 'false' )
# always() && (needs.tests-summarize.result == 'failure')


def test_parse1():
    if_check1 = "(((github.event.action == 'labeled' && (github.event.label.name == 'approved' || github.event.label.name == 'lgtm' || github.event.label.name == 'ok-to-test')) || (github.event.action != 'labeled' && (contains(github.event.pull_request.labels.*.name, 'ok-to-test') || contains(github.event.pull_request.labels.*.name, 'approved') || contains(github.event.pull_request.labels.*.name, 'lgtm')))) && github.repository == 'feast-dev/feast')"

    expr = ExpressionParser(if_check1)

    expr.print_ast()


def test_parse2():
    if_check = "github.event.issue.pull_request\n&& contains(github.event.comment.body, '[test]')\n&& contains(fromJson('[\"OWNER\", \"MEMBER\"]'), github.event.comment.author_association)\n"

    expr = ExpressionParser(if_check)
    expr.print_ast()
    variables = {
        "github.event.issue.pull_request": True,
        "github.event.comment.body": "[test] testing",
        "github.event.comment.author_association": "NONE",
    }

    evaluator = ExpressionEvaluator(variables)
    result = evaluator.evaluate(expr.get_node())

    print(f"Result of the expression '{if_check}' is: {result}")

    assert result is False


def test_parse3():
    if_check = "${{ endsWith(inputs.repository-name, '-enterprise') }}"
    expr = ExpressionParser(if_check)
    expr.print_ast()


def test_parse4():
    if_check = "always() && (needs.get-go-version.result == 'failure' || needs.acceptance-test.result == 'failure')"
    expr = ExpressionParser(if_check)
    expr.print_ast()


def test_parse5():
    if_check = "github.event.deployment_status.state == 'success' && github.event.deployment.environment == 'preview' && github.event.sender.id == 35613825 && github.event.repository.name == 'dev-portal'"
    expr = ExpressionParser(if_check)
    expr.print_ast()
    ExpressionEvaluator()


def test_simple_evaluate():
    # Example usage:
    variables = {"github.event.issue.pull_request": True}
    expression = "github.event.issue.pull_request"
    parser = ExpressionParser(expression)
    ast_root = parser.get_node()

    evaluator = ExpressionEvaluator(variables)
    result = evaluator.evaluate(ast_root)
    print(f"Result of the expression '{expression}' is: {result}")
    assert result is True
