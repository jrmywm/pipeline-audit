FROM ruby:3.3
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install
COPY . .
RUN <<EOF
  chmod +x entrypoint.sh
  chown -R ruby:ruby /app
EOF
CMD ["ruby", "app.rb"]