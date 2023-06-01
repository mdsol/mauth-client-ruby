# frozen_string_literal: true

require 'spec_helper'
require 'mauth/client'

describe MAuth::PrivateKeyHelper do
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048).to_s }
  let(:private_key_newlines_replaced_with_spaces) { private_key.tr("\n", ' ') }
  let(:private_key_no_newlines) { private_key.delete("\n") }
  let(:private_key_invalid) { 'abc' }

  describe 'generate' do
    it 'returns a RSA object' do
      expect(described_class.generate).to be_a_kind_of(OpenSSL::PKey::RSA)
    end
  end

  describe 'load' do
    it 'loads a private key string and returns a RSA object' do
      expect(described_class.load(private_key).to_s).to eq(private_key)
    end

    it 'loads a private key string (newlines are replaced with spaces) and returns a RSA object' do
      expect(described_class.load(private_key_newlines_replaced_with_spaces).to_s).to eq(private_key)
    end

    it 'loads a private key string (newlines are removed) and returns a RSA object' do
      expect(described_class.load(private_key_no_newlines).to_s).to eq(private_key)
    end

    it 'raises an error if the private key string is invalid' do
      expect do
        described_class.load(private_key_invalid)
      end.to raise_error('The private key provided is invalid')
    end
  end
end
