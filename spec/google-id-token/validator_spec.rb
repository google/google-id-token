require "google-id-token/validator"

describe GoogleIDToken::Validator do
  before do
    @private_key = OpenSSL::PKey::RSA.generate(2048)
    public_key = @private_key.public_key
    certificate = OpenSSL::X509::Certificate.new
    certificate.public_key = public_key

    @validator = GoogleIDToken::Validator.new(x509_cert: certificate)
  end

  context 'aud' do
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

  context 'cid' do
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
end
