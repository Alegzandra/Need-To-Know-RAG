.PHONY: install models corpus ingest demo eval test up serve
install:   ## install with dev extras
	pip install -e ".[dev]"
models:    ## pull local models
	ollama pull gpt-oss:20b
	ollama pull bge-m3
corpus:    ## generate the fictional demo corpus
	python scripts/make_corpus.py
ingest:
	ntk ingest data/corpus
demo:
	ntk ask --user mihai "Who is behind the drone flights near substation S-17 and the Port of Calvara?"
	ntk ask --user elena "Who is behind the drone flights near substation S-17 and the Port of Calvara?"
eval:
	ntk eval all
test:
	pytest -q
serve:
	ntk serve --port 8080
up:        ## full stack in containers
	docker compose up -d --build && docker compose --profile setup run --rm ollama-pull
