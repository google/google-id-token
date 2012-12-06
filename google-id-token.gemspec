Gem::Specification.new do |s|
  s.name = 'google-id-token'
  s.version = '1.0.0pre'
  s.date = '2012-11-16'
  s.summary = 'Google ID Token utilities'
  s.description = 'Google ID Token utilities; currently just a parser/checker'
  s.authors = ["Tim Bray", "Bob Aman"]
  s.email = 'tbray@textuality.com'
  s.homepage = 'http://www.tbray.org/ongoing'
  s.files = ["lib/google_id_token.rb"]
  s.add_runtime_dependency "multi_json"
  s.add_runtime_dependency "jwt"
  s.add_development_dependency "fakeweb"
end
