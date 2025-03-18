# frozen_string_literal: true

if defined?(ActiveRecord::Base)
  class ApplicationRecord < ActiveRecord::Base
    self.abstract_class = true
  end
else
  class ApplicationRecord
    def self.inherited(subclass)
      # No-op for non-ActiveRecord environments
    end
  end
end
