package main

import "testing"

func Test_everyone(t *testing.T) {
	type args struct {
		origin string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "first",
			args: args{
				origin: "foo",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := everyone(tt.args.origin); got != tt.want {
				t.Errorf("everyone() = %v, want %v", got, tt.want)
			}
		})
	}
}
