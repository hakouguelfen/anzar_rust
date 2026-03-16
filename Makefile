.PHONY: publish

publish:
	cargo release $(bump) --execute
	git push gitlab && git push gitlab --tags
