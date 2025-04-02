# Use the official Fluent Bit image as the base
FROM fluent/fluent-bit:latest

# Copy the custom configuration files into the image
# Fluent Bit looks for configuration in /fluent-bit/etc/ by default
COPY fluent-bit.conf /fluent-bit/etc/
COPY parsers.conf /fluent-bit/etc/
COPY inputs/ /fluent-bit/etc/inputs/
COPY filters/ /fluent-bit/etc/filters/

# Ensure correct permissions
RUN chmod 644 /fluent-bit/etc/fluent-bit.conf /fluent-bit/etc/parsers.conf && \
    chmod 644 /fluent-bit/etc/inputs/*.conf && \
    chmod 644 /fluent-bit/etc/filters/*.conf

# No explicit CMD or ENTRYPOINT needed unless overriding the base image's default,
# which is typically to run fluent-bit using /fluent-bit/etc/fluent-bit.conf