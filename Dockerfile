FROM node:16-alpine

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD true
ENV CHROMIUM_BIN /usr/bin/chromium-browser

RUN apk update
RUN apk add -u --no-cache build-base nodejs udev chromium ttf-freefont yarn git python3 python3-dev py3-pip zip
RUN git clone https://github.com/AliasIO/wappalyzer.git
WORKDIR /wappalyzer
RUN yarn install
RUN yarn run link

COPY requirement.txt /requirement.txt
RUN pip install -r /requirement.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml

WORKDIR /app
CMD ["python3", "/app/agent/wappalyzer_agent.py"]
