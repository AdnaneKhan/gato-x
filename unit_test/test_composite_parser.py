TEST_COMPOSITE = """
name: ci-lint-charts
description: Lint helm charts

runs:
  using: composite
  steps:
    - name: Checkout repo
      uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
    - name: Print title
      shell: bash
      run: |
        echo "${{ github.event.pull_request.title }}"
"""
