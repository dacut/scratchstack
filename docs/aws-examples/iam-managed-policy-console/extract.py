#!/usr/bin/env python3
import boto3
from bs4 import BeautifulSoup

with open("iam-managed-policy-console.html", "r") as fd:
    data = fd.read()

soup = BeautifulSoup(data, "html.parser")
iam_table = soup.find("iam-table", class_="policies-table")
body = iam_table.find("div", class_="body ng-isolate-scope")

policy_types = {}

for row in body.find_all("div", class_=["row pointer ng-scope", "row pointer ng-scope selected"]):
    policy_name_div = row.find("div", class_="cell ng-scope ng-isolate-scope policy-name")
    policy_name_span = policy_name_div.find("span", class_="ng-scope policy-name-with-icon")
    policy_name_link = policy_name_span.find("a")
    policy_name = policy_name_link.text.strip()

    policy_type_div = row.find("div", class_="cell ng-scope ng-isolate-scope type")
    assert policy_type_div is not None, "Could not find policy type in row: %s" % (row,)
    policy_type_outer_span = policy_type_div.find("span", recursive=False)
    assert policy_type_outer_span is not None
    policy_type_inner_span = policy_type_outer_span.find("span", recursive=False)
    assert policy_type_inner_span is not None
    policy_type = policy_type_inner_span.text.strip()

    policy_types[policy_name] = policy_type

iam = boto3.client("iam")
all_policies = []
for page in iam.get_paginator("list_policies").paginate():
    for policy in page["Policies"]:
        if policy["Arn"].startswith("arn:aws:iam::aws:"):
            all_policies.append(policy)

all_policies.sort(key=lambda policy: policy["PolicyName"].lower())
with open("aws-managed-policies.csv", "w") as fd:
    fd.write("PolicyName\tPath\tType\n")
    for policy in all_policies:
        name = policy["PolicyName"]
        policy_type = policy_types.get(name, "Unknown")
        fd.write(f"{name}\t{policy['Path']}\t{policy_type}\n")
