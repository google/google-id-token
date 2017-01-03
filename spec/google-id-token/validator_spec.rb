require "google-id-token/validator"
require "fakeweb"

shared_examples "validates aud" do
  it 'is all good if aud is the same' do
    token = JWT.encode({ aud: "audience" }, @private_key, "RS256")

    decoded_token = @validator.check(token, "audience")

    expect(@validator.problem).to be_nil
    expect(decoded_token["aud"]).to eq("audience")
  end

  it 'reports error if aud is different' do
    token = JWT.encode({ aud: "differnt_audience" }, @private_key, "RS256")

    decoded_token = @validator.check(token, "audience")

    expect(decoded_token).to be_nil
    expect(@validator.problem).to eq("Token audience mismatch")
  end
end

shared_examples "validates cid" do
  it 'is all good if cid is the same' do
    token = JWT.encode({ aud: "audience", cid: "client_id" }, @private_key, "RS256")

    decoded_token = @validator.check(token, "audience", "client_id")

    expect(@validator.problem).to be_nil
    expect(decoded_token["cid"]).to eq("client_id")
  end

  it 'is all good also if cid comes in the form of azp' do
    token = JWT.encode({ aud: "audience", azp: "client_id" }, @private_key, "RS256")

    decoded_token = @validator.check(token, "audience", "client_id")

    expect(@validator.problem).to be_nil
    expect(decoded_token["azp"]).to eq("client_id")
    expect(decoded_token["cid"]).to eq("client_id")
  end

  it 'reports error if cid is different' do
    token = JWT.encode({ aud: "audience", cid: "different_client_id" }, @private_key, "RS256")

    decoded_token = @validator.check(token, "audience", "client_id")

    expect(decoded_token).to be_nil
    expect(@validator.problem).to eq("Token client-id mismatch")
  end

  it 'reports error if cid is different in the form of azp' do
    token = JWT.encode({ aud: "audience", azp: "different_client_id" }, @private_key, "RS256")

    decoded_token = @validator.check(token, "audience", "client_id")

    expect(decoded_token).to be_nil
    expect(@validator.problem).to eq("Token client-id mismatch")
  end
end

describe GoogleIDToken::Validator do
  before do
    @private_key = OpenSSL::PKey::RSA.generate(2048)
    public_key = @private_key.public_key
    @certificate = OpenSSL::X509::Certificate.new
    @certificate.not_before = Time.now
    @certificate.not_after = Time.now + 365 * 24 * 60 * 60
    @certificate.public_key = public_key
    @certificate.sign(@private_key, OpenSSL::Digest::SHA1.new)
  end

  context "with literal certificate" do
    before do
      @validator = GoogleIDToken::Validator.new(x509_cert: @certificate)
    end

    it_behaves_like "validates aud"
    it_behaves_like "validates cid"
  end

  context "with fetched certificate" do
    before do
      FakeWeb.register_uri(
        :get,
        "https://www.googleapis.com/oauth2/v1/certs",
        body: { :_ => @certificate.to_pem }.to_json
      )

      @validator = GoogleIDToken::Validator.new
    end

    it_behaves_like "validates aud"
    it_behaves_like "validates cid"
  end
end
