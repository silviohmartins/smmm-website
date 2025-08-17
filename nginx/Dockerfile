# Comece com a imagem base do Nginx
FROM nginx:alpine

# Copia a configuração a partir da pasta nginx
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Copia o site estático a partir da pasta static-site
COPY static-site /usr/share/nginx/html