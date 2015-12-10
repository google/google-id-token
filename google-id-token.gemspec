# encoding: utf-8
# Copyright 2012 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Gem::Specification.new do |s|
  s.name = "google-id-token"
  s.version = "1.3.0"

  s.homepage = "https://github.com/google/google-id-token/"
  s.summary = 'Google ID Token utilities'
  s.description = 'Google ID Token utilities; currently just a parser/checker'

  s.files = ["lib/google-id-token.rb", "README.rdoc" ]

  s.add_runtime_dependency "multi_json"
  s.add_runtime_dependency "jwt"

  s.add_development_dependency "fakeweb"
  s.add_development_dependency "rake"
  s.add_development_dependency "rspec"
  s.add_development_dependency "openssl"

  s.authors = ["Tim Bray", "Bob Aman"]
  s.email = 'tbray@textuality.com'
end
