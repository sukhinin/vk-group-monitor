FROM alpine:3.12

RUN apk add --no-cache python3 py3-pip

RUN addgroup -S vkgrpmon && \
    adduser -S -G vkgrpmon -H -h /var/lib/vkgrpmon -s /sbin/nologin -g vkgrpmon vkgrpmon && \
    mkdir /var/lib/vkgrpmon && \
    chown vkgrpmon /var/lib/vkgrpmon

ENV STATE_FILE /var/lib/vkgrpmon/state
COPY vkgrpmon.py /usr/local/bin/vkgrpmon.py
RUN chmod a+x /usr/local/bin/vkgrpmon.py

COPY crontab /etc/crontabs/vkgrpmon
CMD ["/usr/sbin/crond", "-f"]
