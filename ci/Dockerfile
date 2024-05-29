FROM python:3.11-bullseye
RUN python -m pip install --upgrade pip poetry
RUN apt-get update && \
	apt-get install -y --no-install-recommends pandoc texlive texlive-latex-extra && \
	rm -rf /var/lib/apt/lists/*

