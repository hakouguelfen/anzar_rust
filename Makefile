.PHONY: publish

publish:
	cargo release $(bump)
	git push && git push --tags
