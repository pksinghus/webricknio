#--
# webricknio_generator.rb
#
# Author: Pradeep Singh
# Copyright (c) 2012 Pradeep Singh
# All rights reserved.

class WebricknioGenerator < Rails::Generators::Base
  source_root File.expand_path('../', __FILE__)

  def copy_initializer_file
    copy_file "webricknio.rb", "config/webricknio.rb"
  end

end
