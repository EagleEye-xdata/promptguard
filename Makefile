.PHONY: up test demo
up:
	docker compose up --build
test:
	python -m pytest -q
demo:
	bash scripts/demo.sh
