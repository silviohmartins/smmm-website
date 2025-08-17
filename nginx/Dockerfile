# Comece com a imagem base do Nginx
FROM nginx:alpine

# Copie nosso arquivo de configuração para dentro da imagem
COPY nginx.conf /etc/nginx/nginx.conf

# Copie nosso site estático para dentro da imagem
COPY ../static-site /usr/share/nginx/html