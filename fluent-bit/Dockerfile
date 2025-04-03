# Use the official Fluent Bit image as the base
FROM fluent/fluent-bit:latest

# Copy the custom configuration files into the image
# Fluent Bit looks for configuration in /fluent-bit/etc/ by default
COPY fluent-bit.conf /fluent-bit/etc/

# No explicit CMD or ENTRYPOINT needed unless overriding the base image's default,
# which is typically to run fluent-bit using /fluent-bit/etc/fluent-bit.conf