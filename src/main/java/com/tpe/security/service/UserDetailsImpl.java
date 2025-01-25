package com.tpe.security.service;

import com.tpe.domain.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailsImpl implements UserDetails {
    //SS nin istediği userı(UserDetails) oluşturucağız.
    //amac:kendi userımızdan --->userdetailsimpl objesi oluşturacağız

    private Long id;
    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    //kendi user-->userdetails
    public static UserDetailsImpl build(User user){
        //roller-->SimpleGrantedAuthority implements GrantedAuthority
        List<SimpleGrantedAuthority> authorities=
                user.getRoles().stream().
                        map(role -> new SimpleGrantedAuthority(role.getType().name())).
                        collect(Collectors.toList());
        //userdetailsimpl
        return new UserDetailsImpl(user.getId(), user.getUserName(), user.getPassword(), authorities);
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}