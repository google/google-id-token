# GoogleIDToken

GoogleIDToken verifies the integrity of ID tokens generated by Google authentication servers ([docs](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token))

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'google-id-token'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install google-id-token

## Usage

GoogleIDToken currently provides a single useful class `Validator`, which provides a single method `#check`, which parses and validates the integrity of an ID Token allegedly generated by Google auth servers.

```ruby
validator = GoogleIDToken::Validator.new
begin
  payload = validator.check(token, required_audience, optional_client_id)
  email = payload['email']
rescue GoogleIDToken::ValidationError => e
  report "Cannot validate: #{e}"
end
```

## Params

| Key                | type   | Description          |
| ------------------ | ------ | -------------------- |
| token              | string | The JWT token        |
| required_audience  | string | The google client id |
| optional_client_id | string | The google client id |

## Example response

```ruby
{
  "iss": "https://accounts.google.com",
  "email": "abcdefg123456@gmail.com",
  "sub": "1234567890123456789",
  "aud": "xyz1.abc.com,xyz2.abc.com",
  "foo": "foo.foo.foo.foo",
  "bar": "bar.bar.bar.bar",
  "azp": "98765432109876543210",
  "exp": "1642809446",
  "iat": "1642805846"
}
```

## Configuration

Creating a new validator takes a single optional hash argument. If the hash has an entry for :x509_key, that value is taken to be a key as created by OpenSSL::X509::Certificate.new, and the token is validated using that key. If there is no such entry, the keys are fetched from the Google certs endpoint https://www.googleapis.com/oauth2/v1/certs. The certificates are cached for some time (default: 1 hour) which can be configured by adding the :expiry argument to the initialization hash (in seconds).

### expiry

Expiry defines the the time (in seconds) in which the cached Google certificates are valid.

```ruby
GoogleIDToken::Validator.new(expiry: 1800) # 30 minutes
```

### x509_cert

x509_cert can be provided to manually define a certificate to validate the tokens.

```ruby
cert = OpenSSL::X509::Certificate.new(File.read('my-cert.pem'))
validator = GoogleIDToken::Validator.new(x509_cert: cert)
```
