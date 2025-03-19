# frozen_string_literal: true

# Mock ActiveRecord::Base for testing
module ActiveRecord
  class Base
    def self.belongs_to(name, options = {}); end

    def self.validates(name, options = {}); end

    def self.validates_presence_of(name); end

    def self.validates_uniqueness_of(name, options = {}); end

    def self.serialize(name, format); end

    def self.has_many(name, options = {}); end
  end
end

# Mock JSON for testing
module JSON
  def self.dump(obj)
    obj.to_s
  end

  def self.load(str)
    str
  end
end

# Mock JWT for Apple provider testing
module JWT
  def self.encode(_payload, _key, _algorithm)
    "mock-jwt-token"
  end

  def self.decode(_token, _key, _verify, _options = {})
    [{ "sub" => "123456789" }, { "alg" => "RS256" }]
  end
end

# Create a Struct for credentials and config
CredentialsStruct = Struct.new(:clavis)
ProvidersStruct = Struct.new(:google)
GoogleStruct = Struct.new(:client_id, :client_secret)
ConfigStruct = Struct.new(:filter_parameters)

# Mock Rails for testing
module Rails
  def self.env
    @env ||= ActiveSupport::StringInquirer.new("test")
  end

  def self.logger
    @logger ||= Logger.new($stdout).tap { |l| l.level = Logger::WARN }
  end

  def self.application
    @application ||= Application.new
  end

  class Application
    def credentials
      @credentials ||= begin
        google_config = GoogleStruct.new(
          "google_client_id_from_credentials",
          "google_client_secret_from_credentials"
        )
        providers = ProvidersStruct.new(google_config)
        CredentialsStruct.new({ encryption_key: "test_encryption_key_from_credentials", providers: providers })
      end
    end

    def config
      @config ||= ConfigStruct.new([])
    end

    def respond_to?(method_name)
      %i[credentials config].include?(method_name.to_sym) || super
    end
  end
end

# Mock ActiveSupport::StringInquirer for testing
module ActiveSupport
  class StringInquirer < String
    def method_missing(method_name, *arguments)
      if method_name.to_s.end_with?("?")
        self == method_name.to_s[0..-2]
      else
        super
      end
    end

    def respond_to_missing?(method_name, include_private = false)
      method_name.to_s.end_with?("?") || super
    end
  end
end

# Add inquiry method to String for testing
class String
  def inquiry
    ActiveSupport::StringInquirer.new(self)
  end
end

# Mock Logger for testing
class Logger
  def initialize(output)
    @output = output
    @level = 0
  end

  attr_accessor :level

  def info(message); end

  def debug(message = nil); end

  def warn(message); end

  def error(message); end
end

# Custom Hash-like class to replace OpenStruct
class HashStruct
  def initialize(hash = nil)
    @table = {}
    hash&.each_pair { |k, v| @table[k.to_sym] = v }
  end

  def method_missing(method, *args)
    if method.to_s.end_with?("=")
      @table[method.to_s.chop.to_sym] = args.first
    else
      @table[method]
    end
  end

  def respond_to_missing?(_method, _include_private = false)
    true
  end

  def to_h
    @table.dup
  end

  def dig(*keys)
    result = @table
    keys.each do |key|
      return nil unless result.is_a?(Hash) || result.is_a?(HashStruct)

      result = result.is_a?(HashStruct) ? result.send(key) : result[key.to_sym]
      return nil if result.nil?
    end
    result
  end

  def present?
    !@table.empty?
  end
end
