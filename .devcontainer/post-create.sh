mkdir -p $HOME/.local/share/fonts
wget https://github.com/ryanoasis/nerd-fonts/releases/download/v3.1.1/0xProto.zip
unzip 0xProto.zip -d $HOME/.local/share/fonts
rm 0xProto.zip

starship preset nerd-font-symbols -o ~/.config/starship.toml
