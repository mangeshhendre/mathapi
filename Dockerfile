FROM scratch

ADD spiglassapi /spiglassapi

EXPOSE 8443

ENTRYPOINT ["/spiglassapi"]