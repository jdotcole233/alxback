<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

class ALXAuthenticationController extends Controller
{
    public function alx_register(Request $request)
    {
        $validation_rules = [
            'name' => 'required',
            'email' => 'email|required|unique:users',
            'password' => 'required|confirmed'
        ];
        $user_created = [];
        $access_token = "";

       DB::transaction(function () use ($validation_rules, &$user_created, &$access_token, $request) {
           $user_validated = $request->validate($validation_rules);
           $hash_password = Hash::make($user_validated['password']);
           $user_validated['password'] = $hash_password;

           $user_created = User::create($user_validated);
           $access_token = $user_created->createToken('authToken')->accessToken;
       });

       return response()->json([
           'user' => $user_created,
           'access_token' => $access_token
       ]);
    }


    public function alx_login(Request $request)
    {
        $validation_rules =[
            'email' => 'required',
            'password' => 'required'
        ];

        $login_credentials = $request->validate($validation_rules);

        if (!auth()->attempt($login_credentials)) {
            return response()->json(['message' => 'invalid credentials'], 400);
        }

        $logged_user = auth()->user();
        $access_token = $logged_user->createToken('authToken')->accessToken;

        return response()->json([
            'user' => $logged_user,
            'access_token' => $access_token
        ]);
    }



}
