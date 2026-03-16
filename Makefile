.PHONY: publish

publish:
	cargo release $(bump) --execute
	git push && git push --tags
