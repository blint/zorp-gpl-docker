FROM debian:buster-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl gpg ca-certificates tcpdump
RUN echo 'deb https://download.opensuse.org/repositories/security:/Zorp:/7:/0:/7/Debian_10/ /' | tee /etc/apt/sources.list.d/security:Zorp:7:0:7.list
RUN curl -fsSL https://download.opensuse.org/repositories/security:Zorp:7:0:7/Debian_10/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_Zorp_7_0_7.gpg > /dev/null
RUN apt-get update && apt-get install -y --no-install-recommends zorp zorp-modules kzorpd python-passlib
COPY htpasswd /etc/zorp/htpasswd
RUN mkdir /var/run/zorp && chown zorp.zorp /var/run/zorp && chmod 770 /var/run/zorp
COPY instances.conf /etc/zorp/instances.conf
COPY policy.py /etc/zorp/policy.py
EXPOSE 3138/udp
ENTRYPOINT zorp -Fl --as default --threads 1000 --verbose 3 --log-spec '*.summary:4,*.accounting:4' --log-tags --enable-core --policy /etc/zorp/policy.py --user zorp --group zorp
