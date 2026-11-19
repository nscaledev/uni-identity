# Specs that called Skip(), as "reason: full spec name". A spec that a filter left out has no
# message, and one skipped after an earlier failure (a failed BeforeAll or ordered spec) is
# reported as that failure, not a skip. A Skip() in BeforeSuite shows only on the BeforeSuite
# node; its specs look filtered.
.[].SpecReports[]
| select((.LeafNodeType == "It" or .LeafNodeType == "BeforeSuite") and .State == "skipped")
| (.Failure.Message // "") as $reason
| select($reason != "" and ($reason | test("^Spec skipped because (an earlier spec|a BeforeAll node) .*failed") | not))
| ((.ContainerHierarchyTexts // []) + [.LeafNodeText] | map(select(. != "")) | join(" > ")) as $name
| "\($reason): \(if $name == "" then .LeafNodeType else $name end)"
